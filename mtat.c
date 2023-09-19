#include "mtat.h"

/*
 * Module parameters
 */
static int migrate_on = 0;
module_param(migrate_on, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

/*
 * Page list related variables and functions
 *
 * lock 규칙:
 * - list_del, list_add 모두 mtat_page->lock,  page_list->lock 잡은 후 수행.
 *
 * lock 순서:
 *  mtat_page->lock
 *    page_list->lock, lock
 */
static atomic_t global_clock[MAX_PIDS];
static int pids[MAX_PIDS];
static spinlock_t lock;

static struct page_list f_pages[NR_MEM_TYPES]; // free_pages
static struct page_list hot_pages[MAX_PIDS][NR_MEM_TYPES];
static struct page_list cold_pages[MAX_PIDS][NR_MEM_TYPES];

struct mtat_page *alloc_and_init_mtat_page(struct page *page)
{
	struct mtat_page *m_page = kmalloc(sizeof(*m_page), GFP_KERNEL);

	if (!m_page)
		return NULL;

	m_page->page = page;
	m_page->pfn = page_to_pfn(page) << PAGE_SHIFT >> HPAGE_SHIFT;
	memset(m_page->accesses, 0, sizeof(m_page->accesses));
	m_page->local_clock = 0;
	m_page->hotness = COLD;
	m_page->pids_idx = PID_NONE;
	m_page->nid = page_to_nid(page);
	INIT_LIST_HEAD(&m_page->list);
	spin_lock_init(&m_page->lock);

	return m_page;
}

int get_num_pages(struct page_list *pl)
{
	int num_pages;

	spin_lock(&pl->lock);
	num_pages = pl->num_pages;
	spin_unlock(&pl->lock);

	return num_pages;
}

void page_list_del(struct list_head *page, struct page_list *pl)
{
	spin_lock(&pl->lock);
	list_del(page);
	pl->num_pages--;
	spin_unlock(&pl->lock);
}

void page_list_add(struct list_head *page, struct page_list *pl)
{
	spin_lock(&pl->lock);
	list_add(page, &pl->list);
	pl->num_pages++;
	spin_unlock(&pl->lock);
}

void init_page_list(struct page_list *pl)
{
	INIT_LIST_HEAD(&pl->list);
	pl->num_pages = 0;
	spin_lock_init(&pl->lock);
}

static int pid_to_idx(int pid)
{
	int i, idx = PID_NONE;

	spin_lock(&lock);
	for (i = 0; i < MAX_PIDS; i++) {
		if (pid == pids[i]) {
			idx = i;
			break;
		}
	}
	spin_unlock(&lock);

	return idx;
}

/*
 * Hashtable for MTAT page management
 */
static struct rhashtable *hashtable = NULL;
static struct rhashtable_params params = {
	.head_offset = offsetof(struct mtat_page, node),
	.key_offset = offsetof(struct mtat_page, pfn),
	.key_len = sizeof(uint64_t),
	.automatic_shrinking = false,
	.min_size = 0xffff,
};

static void rh_free_fn(void *ptr, void *arg)
{
	struct mtat_page *m_page = ptr;
	kfree(m_page);
}

static int init_hashtable(void)
{
	int err;

	hashtable = kmalloc(sizeof(*hashtable), GFP_KERNEL);
	if (!hashtable) {
		pr_err("Failed to allocate hashtable\n");
		return -1;
	}

	err = rhashtable_init(hashtable, &params);
	if (err) {
		kfree(hashtable);
		pr_err("Failed to init hashtable\n");
		return -1;
	}

	return 0;
}

static void destroy_hashtable(void)
{
	if (hashtable)
		rhashtable_free_and_destroy(hashtable, rh_free_fn, NULL);
}

/*
 * kmonitord thread for debugging
 */
static struct task_struct *kmonitord;

static void print_num_pages(void)
{
	int i, j;

	for (i = 0; i < MAX_PIDS; i++) {
		if (pids[i] == PID_NONE)
			continue;
		pr_info("pid: %d\n", pids[i]);
		for (j = 0; j < NR_MEM_TYPES; j++) {
			pr_info("--numa node: %d\n", j);
			pr_info("----free_pages: %d\n", get_num_pages(&f_pages[j]));
			pr_info("----hot_pages: %d\n", get_num_pages(&hot_pages[i][j]));
			pr_info("----cold_pages: %d\n", get_num_pages(&cold_pages[i][j]));
		}
	}
}


static int kmonitord_main(void *data)
{
	while (!kthread_should_stop()) {
		print_num_pages();

		ssleep(4);
	}

	return 0;
}


/*
 * PEBS related variables and functions
 */
static struct perf_event **events;
static size_t configs[] = { DRAM_READ, PMEM_READ, STORE_ALL };

// m_page->lock을 잡고 호출해야함.
static void make_hot_page(struct mtat_page *m_page, int pid_idx, int nid)
{
	m_page->hotness = HOT;
	page_list_del(&m_page->list, &cold_pages[pid_idx][nid]);
	page_list_add(&m_page->list, &hot_pages[pid_idx][nid]);
}

// m_page->lock을 잡고 호출해야함.
static void make_cold_page(struct mtat_page *m_page, int pid_idx, int nid)
{
	m_page->hotness = COLD;
	page_list_del(&m_page->list, &hot_pages[pid_idx][nid]);
	page_list_add(&m_page->list, &cold_pages[pid_idx][nid]);
}

static uint64_t perf_virt_to_phys(u64 virt)
{
	uint64_t phys_addr = 0;

	if (!virt)
		return 0;

	if (virt >= TASK_SIZE) {
		if (virt_addr_valid((void *)(uintptr_t)virt) &&
		    !(virt >= VMALLOC_START && virt < VMALLOC_END))
			phys_addr = (uint64_t)virt_to_phys((void *)(uintptr_t)virt);
	} else {
		if (current->mm != NULL) {
			struct page *p;
			pagefault_disable();
			if (get_user_page_fast_only(virt, 0, &p)) {
				phys_addr = (page_to_pfn(p) << PAGE_SHIFT) + virt % PAGE_SIZE;
				put_page(p);
			}
			pagefault_enable();
		}
	}
	return phys_addr;
}

static void pebs_sample(struct perf_event *event, 
		struct perf_sample_data *data, struct pt_regs *regs)
{
	uint64_t pfn;
	int nid, pid, pid_idx;
	bool write = event->attr.config == STORE_ALL;
	int access_type = write ? WRITE_MTAT : READ_MTAT;
	struct mtat_page *m_page = NULL;

	pfn = perf_virt_to_phys(data->addr) >> HPAGE_SHIFT;
	m_page = rhashtable_lookup_fast(hashtable, &pfn, params);
	if (!m_page) {
		return;
	}

	
	spin_lock(&m_page->lock);

	pid_idx = m_page->pids_idx;
	nid = m_page->nid;
	pid = pids[pid_idx]; // pids[i]는 한번 쓰이면 값이 변하지 않음. lock잡을 필요 X


	m_page->accesses[access_type]++;

	if (m_page->accesses[WRITE_MTAT] >= HOT_WRITE_THRESHOLD) {
		if (m_page->hotness != HOT)
			make_hot_page(m_page, pid_idx, nid);
	} else if (m_page->accesses[READ_MTAT] >= HOT_READ_THRESHOLD) {
		if (m_page->hotness != HOT)
			make_hot_page(m_page, pid_idx, nid);
	} else if (m_page->accesses[WRITE_MTAT] < HOT_WRITE_THRESHOLD &&
			m_page->accesses[READ_MTAT] < HOT_READ_THRESHOLD) {
		if (m_page->hotness != COLD)
			make_cold_page(m_page, pid_idx, nid);
	}

	m_page->accesses[access_type] >>= atomic_read(&global_clock[pid_idx]) - m_page->local_clock;
	m_page->local_clock = atomic_read(&global_clock[pid_idx]);
	if (m_page->accesses[access_type] > COOL_THRESHOLD) {
		atomic_inc(&global_clock[pid_idx]);
	}

	spin_unlock(&m_page->lock);
}

static void pebs_start(void)
{
	size_t config, cpu, ncpus = num_online_cpus();
	static struct perf_event_attr wd_hw_attr = {
		.type = PERF_TYPE_RAW,
		.size = sizeof(struct perf_event_attr),
		.pinned = 0,
		.disabled = 1,
		.precise_ip = 2,
		.sample_id_all = 1,
		.exclude_kernel = 1,
		.exclude_guest = 1,
		.exclude_hv = 1,
		.exclude_user = 0,
		.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
			       PERF_SAMPLE_WEIGHT | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR,
	};

	events = vmalloc(ncpus * ARRAY_SIZE(configs) * sizeof(*events));
	if (!events) {
		pr_err("Failed to allocate perf_event\n");
		return;
	}

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			size_t idx = config * ncpus + cpu;
			wd_hw_attr.config = configs[config];
			wd_hw_attr.sample_period = SAMPLE_PERIOD_PEBS;
			events[idx] = 
				perf_event_create_kernel_counter(&wd_hw_attr,
						cpu, NULL, pebs_sample, NULL);
			if (IS_ERR(events[idx])) {
				pr_err("Failed to create event %lu on cpu %lu\n", configs[config], cpu);
				return;
			}
			perf_event_enable(events[idx]);
		}
	}
}
static void pebs_stop(void)
{
	size_t config, cpu, ncpus = num_online_cpus();

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			size_t idx = config * ncpus + cpu;
			perf_event_disable(events[idx]);
			perf_event_release_kernel(events[idx]);
		}
	}

	vfree(events);
}

/*
 * Page allocation & free
 */
static int add_new_page(struct page *page)
{
	int err, nid;
	struct mtat_page *m_page = alloc_and_init_mtat_page(page);	

	nid = page_to_nid(page);
	page_list_add(&m_page->list, &f_pages[nid]);
	err = rhashtable_insert_fast(hashtable, &m_page->node, params);
	if (err) {
		kfree(m_page);
		pr_err("Failed to insert mtat_page info hashtable\n");
		return -1;
	}

	return 0;
}

static int add_freed_page(struct page *page)
{
	uint64_t pfn = page_to_pfn(page) << PAGE_SHIFT >> HPAGE_SHIFT;
	struct mtat_page *m_page = rhashtable_lookup_fast(hashtable, &pfn, params);

	if (!m_page) {
		pr_err("Didn't find page %llu\n", pfn);
		return 0;
	}

	spin_lock(&m_page->lock);

	if (m_page->hotness == HOT)
		page_list_del(&m_page->list, &hot_pages[m_page->pids_idx][m_page->nid]);
	else
		page_list_del(&m_page->list, &cold_pages[m_page->pids_idx][m_page->nid]);
	page_list_add(&m_page->list, &f_pages[m_page->nid]);

	spin_unlock(&m_page->lock);

	return 0;
}

static void build_page_list(void)
{
	int i, j, nid, nb_pages = 0;
	struct hstate *h;
	struct page *page;
	//bool pin = !!(current->flags & PF_MEMALLOC_PIN);

	spin_lock_init(&lock);
	memset(global_clock, 0, sizeof(global_clock));
	for (i = 0; i < NR_MEM_TYPES; i++) 
		init_page_list(&f_pages[i]);
	for (i = 0; i < MAX_PIDS; i++) {
		pids[i] = PID_NONE;
		for (j = 0; j < NR_MEM_TYPES; j++) {
			init_page_list(&hot_pages[i][j]);
			init_page_list(&cold_pages[i][j]);
		}
	}

	for_each_hstate(h) {
		for (nid = 0; nid < NR_MEM_TYPES; nid++) {
			list_for_each_entry(page, &h->hugepage_freelists[nid], lru) {
				//if (pin && !is_pinnable_page(page))
				//	continue;

				if (PageHWPoison(page)) {
					pr_info("poison\n");
					continue;
				}

				nb_pages++;
				if (add_new_page(page) != 0)
					break;
			}
		}
	}

	pr_info("Successfully created a list of %d pages\n", nb_pages);
}

static void reserve_page(struct hstate *h, int nid, pid_t pid, 
		struct mtat_page *m_page)
{
	int i;

	spin_lock(&lock);
	for (i = 0; i < MAX_PIDS; i++) {
		if (pids[i] == PID_NONE || pids[i] == pid)
			break;
	}
	if (i == MAX_PIDS) {
		pr_err("Too many pids!\n");
		spin_unlock(&lock);
		return;
	}
	if (pids[i] == PID_NONE)
		pids[i] = pid;
	spin_unlock(&lock);

	spin_lock(&m_page->lock);

	m_page->local_clock = atomic_read(&global_clock[i]);
	m_page->hotness = COLD;
	m_page->pids_idx = i;
	m_page->nid = nid;
	memset(m_page->accesses, 0, sizeof(m_page->accesses));
	page_list_del(&m_page->list, &f_pages[nid]);
	page_list_add(&m_page->list, &cold_pages[i][nid]);

	spin_unlock(&m_page->lock);


	list_move(&m_page->page->lru, &h->hugepage_activelist);
	set_page_count(m_page->page, 1);
	ClearHPageFreed(m_page->page);
	h->free_huge_pages--;
	h->free_huge_pages_node[nid]--;
}

static struct page *__mtat_allocate_page(struct hstate *h, int nid, pid_t pid)
{
	struct page *page = NULL;
	struct mtat_page *m_page = NULL;
	int i;

	lockdep_assert_held(&hugetlb_lock);

	for (i = 0; i < NR_MEM_TYPES; i++) {
		spin_lock(&f_pages[i].lock);
		m_page = list_first_entry_or_null(&f_pages[i].list, struct mtat_page, list);
		spin_unlock(&f_pages[i].lock);

		if (m_page)
			break;
	}

	if (m_page) {
		page = m_page->page;	
		reserve_page(h, i, pid, m_page);
	}

	return page;
}

static struct page *mtat_allocate_page(struct hstate *h, int nid)
{
	return __mtat_allocate_page(h, nid, current->tgid);
}

static struct page *mtat_free_page(struct hstate *h, struct page *page)
{
	int nid = page_to_nid(page);

	lockdep_assert_held(&hugetlb_lock);
	VM_BUG_ON_PAGE(page_count(page), page);

	list_move(&page->lru, &h->hugepage_freelists[nid]);
	h->free_huge_pages++;
	h->free_huge_pages_node[nid]++;
	SetHPageFreed(page);

	add_freed_page(page);

	return page;
}

/*
 * Migration daemon
 */
static struct task_struct *kmigrated;

static struct page *mtat_alloc_migration_target(struct page *old, unsigned long private)
{
	struct hstate *h = page_hstate(old);
	struct migration_target_control *mtc = (void*)private;
	struct mtat_page *m_page = NULL;
	struct page *page = NULL;

	spin_lock(&f_pages[mtc->nid].lock);
	m_page = list_first_entry_or_null(&f_pages[mtc->nid].list, struct mtat_page, list);
	spin_unlock(&f_pages[mtc->nid].lock);

	if (m_page) {
		page = m_page->page;
		reserve_page(h, mtc->nid, mtc->pid, m_page);
	}

	return page;
}

static unsigned int migrate_folio_list(struct list_head *folio_list, int nid, int pid)
{
	unsigned int nr_migrated_pages = 0;
	struct page *page;
	struct page *page2;

	struct migration_target_control mtc = {
		.nid = nid,
		.pid = pid
	};

	if (list_empty(folio_list))
		return 0;

	if (migrate_pages(folio_list, mtat_alloc_migration_target,
				NULL, (unsigned long)&mtc, MIGRATE_SYNC,
				MR_NUMA_MISPLACED, &nr_migrated_pages)) {
		pr_err("migration partially failed.\n");
		list_for_each_entry_safe(page, page2, folio_list, lru) {
			putback_active_hugepage(page);
		}
	}

	return nr_migrated_pages;
}

static void solorun_migration(void)
{
	LIST_HEAD(promote_folios);
	LIST_HEAD(demote_folios);
	unsigned int max_demote, nr_free, nr_promote, nr_demote, tmp;
	struct mtat_page *m_page = NULL;

	pr_info("%s\n", __func__);

	nr_free = get_num_pages(&f_pages[FASTMEM]);
	max_demote = get_num_pages(&cold_pages[0][FASTMEM]);
	nr_promote = min(nr_free + max_demote, (unsigned int)get_num_pages(&hot_pages[0][SLOWMEM]));
	nr_demote = 0;

	tmp = 0;
	spin_lock(&hot_pages[0][SLOWMEM].lock);
	list_for_each_entry(m_page, &hot_pages[0][SLOWMEM].list, list) {
		if (tmp == nr_promote)
			break;

		if (isolate_hugetlb(m_page->page, &promote_folios))
			continue;
		tmp++;
	}
	spin_unlock(&hot_pages[0][SLOWMEM].lock);

	if (nr_promote == 0)
		goto out;

	nr_demote = 0;
	spin_lock(&cold_pages[0][FASTMEM].lock);
	list_for_each_entry(m_page, &cold_pages[0][FASTMEM].list, list) {
		if (nr_demote >= (nr_promote - nr_free))
			break;

		if (isolate_hugetlb(m_page->page, &demote_folios))
			continue;
		nr_demote++;
	}
	spin_unlock(&cold_pages[0][FASTMEM].lock);

out:

	pr_info("Expected demoted pages: %u\n", nr_demote);
	pr_info("Expected promoted pages: %u\n", nr_promote);

	nr_demote = migrate_folio_list(&demote_folios, SLOWMEM, pids[0]);
	nr_promote = migrate_folio_list(&promote_folios, FASTMEM, pids[0]);

	pr_info("Real demoted pages: %u\n", nr_demote/512);
	pr_info("Real promoted pages: %u\n", nr_promote/512);
}

static void corun_migration(void)
{
	pr_info("%s\n", __func__);
}

static void hemem_migration(void)
{
	pr_info("%s\n", __func__);
}

static void test_migration(void)
{
	LIST_HEAD(demote_folios);
	unsigned int max_demote, nr_demote;
	struct mtat_page *m_page = NULL;
	struct migration_target_control mtc;

	pr_info("%s\n", __func__);

	max_demote = get_num_pages(&cold_pages[0][FASTMEM]);

	if (max_demote <= 0)
		return;

	nr_demote = 0;
	spin_lock(&cold_pages[0][FASTMEM].lock);
	list_for_each_entry(m_page, &cold_pages[0][FASTMEM].list, list) {
		if (isolate_hugetlb(m_page->page, &demote_folios))
			continue;
		nr_demote++;
		break;
	}
	spin_unlock(&cold_pages[0][FASTMEM].lock);

	pr_info("Expected demoted pages: %u\n", nr_demote);
	mtc.nid = SLOWMEM;
	mtc.pid = pids[0];
	migrate_pages(&demote_folios, mtat_alloc_migration_target,
				NULL, (unsigned long)&mtc, MIGRATE_SYNC,
				MR_NUMA_MISPLACED, &nr_demote);
	pr_info("Real demoted pages: %u\n", nr_demote/512);
}

static void do_migration(void)
{
	switch(MTAT_MIGRATION_MODE) {
	case SOLORUN:
		solorun_migration();
		break;
	case CORUN:
		corun_migration();
		break;
	case HEMEM:
		hemem_migration();
		break;
	case TEST_MODE:
		test_migration();
		break;
	}
}

static int kmigrated_main(void *data)
{
	while(!kthread_should_stop()) {
		print_num_pages();
		if (migrate_on)
			do_migration();
		ssleep(5);
	}

	return 0;
}

/*
 * MTAT initialization
 */
int init_module(void)
{
	if (init_hashtable())
		return -1;

	build_page_list();

	set_dequeue_hook(mtat_allocate_page);
	set_enqueue_hook(mtat_free_page);

	pebs_start();

	if (!ENABLE_MONITOR)
		goto kmigrated_label;

	kmonitord = kthread_run(kmonitord_main, NULL, "kmonitord");
	if (IS_ERR(kmonitord)) {
		pr_err("Failed to create kmonitord\n");
	}

kmigrated_label:
	if (!ENABLE_MIGRATION)
		goto out;

	kmigrated = kthread_run(kmigrated_main, NULL, "kmigrated");
	if (IS_ERR(kmigrated)) {
		pr_err("Failed to create kmigrated\n");
	}

out:
	pr_info("Successfully insert MTAT module\n");
	return 0;
}

/*
 * MTAT exit
 */
void cleanup_module(void)
{
	if (ENABLE_MIGRATION)
		kthread_stop(kmigrated);
	if (ENABLE_MONITOR)
		kthread_stop(kmonitord);

	pebs_stop();

	set_dequeue_hook(NULL);
	set_enqueue_hook(NULL);

	destroy_hashtable();

	pr_info("Remove MTAT module\n");
}

MODULE_AUTHOR("Minho Kim <mhkim@dgist.ac.kr>");
MODULE_DESCRIPTION("Multi-Tenant-Aware Tiered Memory Management");
MODULE_LICENSE("GPL v2");
