#include "mtat.h"

/*
 * Page list related variables
 */
static uint64_t global_clock[MAX_PIDS];
static int pids[MAX_PIDS];
static int num_pages[MAX_PIDS][NR_MEM_TYPES][NR_HOTNESS_TYPES];
static struct list_head f_pages[NR_MEM_TYPES]; // free_pages
static struct list_head hot_pages[MAX_PIDS][NR_MEM_TYPES];
static struct list_head cold_pages[MAX_PIDS][NR_MEM_TYPES];
// TODO: lock 최적화 하기 (리스트 별로 lock 별도로 관리 + page 별로 락 관리)
static spinlock_t lock;

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
 * kthread for debugging
 */
static struct task_struct *kmonitord;

static void print_num_pages(void)
{
	int i, j, k;

	for (i = 0; i < MAX_PIDS; i++) {
		if (pids[i] == PID_NONE)
			continue;
		pr_info("pid: %d\n", pids[i]);
		for (j = 0; j < NR_MEM_TYPES; j++) {
			pr_info("--numa node: %d\n", j);
			for (k = 0; k < NR_HOTNESS_TYPES; k++) {
				if (k == HOT)
					pr_info("----hot_pages: %d\n", num_pages[i][j][k]);
				else
					pr_info("----cold_pages: %d\n", num_pages[i][j][k]);
			}
		}
	}
}


static int kmonitord_main(void *data)
{
	while (!kthread_should_stop()) {
		print_num_pages();

		ssleep(1);
	}

	return 0;
}


/*
 * PEBS related variables and functions
 */
static struct perf_event **events;
static size_t configs[] = { DRAM_READ, PMEM_READ, STORE_ALL };

static void make_hot_page(struct mtat_page *m_page, int pid_idx, int nid)
{
	m_page->hotness = HOT;
	list_move(&m_page->list, &hot_pages[pid_idx][nid]);
	num_pages[pid_idx][nid][COLD]--;
	num_pages[pid_idx][nid][HOT]++;
}

static void make_cold_page(struct mtat_page *m_page, int pid_idx, int nid)
{
	m_page->hotness = COLD;
	list_move(&m_page->list, &cold_pages[pid_idx][nid]);
	num_pages[pid_idx][nid][HOT]--;
	num_pages[pid_idx][nid][COLD]++;
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
	//pr_info("sampled pfn: %lu\n", pfn);
	m_page = rhashtable_lookup_fast(hashtable, &pfn, params);
	if (!m_page) {
		return;
	}
	//pr_info("%s: Found mtat_page from hashtable\n", __func__);

	
	spin_lock(&lock);

	pid_idx = m_page->pids_idx;
	nid = m_page->nid;
	pid = pids[pid_idx];


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

	m_page->accesses[access_type] >>= global_clock[pid_idx] - m_page->local_clock;
	m_page->local_clock = global_clock[pid_idx];
	if (m_page->accesses[access_type] > COOL_THRESHOLD)
		global_clock[pid_idx]++;

	spin_unlock(&lock);
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

static int add_new_page(struct page *page)
{
	int i, err;
	struct mtat_page *m_page = kmalloc(sizeof(*m_page), GFP_KERNEL);
	if (!m_page) {
		pr_err("Failed to allocate mtat_page\n");
		return -1;
	}

	m_page->page = page;
	m_page->pfn = page_to_pfn(page) << PAGE_SHIFT >> HPAGE_SHIFT;
	pr_info("inserted pfn: %llu\n", m_page->pfn);
	INIT_LIST_HEAD(&m_page->list);
	list_add_tail(&m_page->list, &f_pages[page_to_nid(page)]);
	for (i = 0; i < NR_ACCESS_TYPES; i++)
		m_page->accesses[i] = 0;

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
	int nid = page_to_nid(page);
	struct mtat_page *m_page = rhashtable_lookup_fast(hashtable, &pfn, params);

	if (!m_page) {
		pr_err("Didn't find page %llu\n", pfn);
		return 0;
	}

	spin_lock(&lock);
	list_move(&m_page->list, &f_pages[nid]);
	num_pages[m_page->pids_idx][nid][m_page->hotness]--;

	print_num_pages();

	spin_unlock(&lock);

	return 0;
}

static void build_page_list(void)
{
	int i, j, k, nid, nb_pages = 0;
	struct hstate *h;
	struct page *page;
	//bool pin = !!(current->flags & PF_MEMALLOC_PIN);

	spin_lock_init(&lock);
	memset(global_clock, 0, sizeof(global_clock));
	for (i = 0; i < NR_MEM_TYPES; i++)
		INIT_LIST_HEAD(&f_pages[i]);
	for (i = 0; i < MAX_PIDS; i++) {
		pids[i] = PID_NONE;
		for (j = 0; j < NR_MEM_TYPES; j++) {
			INIT_LIST_HEAD(&hot_pages[i][j]);
			INIT_LIST_HEAD(&cold_pages[i][j]);
			for (k = 0; k < NR_HOTNESS_TYPES; k++)
				num_pages[i][j][k] = 0;
		}
	}

	for_each_hstate(h) {
		for (nid = 0; nid < NR_MEM_TYPES; nid++) {
			list_for_each_entry(page, &h->hugepage_freelists[nid], lru) {
				//if (pin && !is_pinnable_page(page))
				//	continue;

				if (PageHWPoison(page))
					continue;

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
		return;
	}

	m_page->local_clock = global_clock[i];
	m_page->hotness = COLD;
	m_page->pids_idx = i;
	m_page->nid = nid;
	pids[i] = pid;
	list_move(&m_page->list, &cold_pages[i][nid]);
	num_pages[i][nid][COLD]++;

	spin_unlock(&lock);

	list_move(&m_page->page->lru, &h->hugepage_activelist);
	set_page_count(m_page->page, 1);
	ClearHPageFreed(m_page->page);
	h->free_huge_pages--;
	h->free_huge_pages_node[nid]--;
}

static struct page *__mtat_allocate_page(struct hstate *h, int nid, pid_t pid)
{
	struct page *allocated_page = NULL;
	struct mtat_page *m_page = NULL;

	lockdep_assert_held(&hugetlb_lock);

	m_page = list_first_entry_or_null(&f_pages[nid], struct mtat_page, list);

	if (m_page) {
		allocated_page = m_page->page;	
		reserve_page(h, nid, pid, m_page);
	}

	return allocated_page;
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

int init_module(void)
{
	if (init_hashtable())
		return -1;

	build_page_list();

	set_dequeue_hook(mtat_allocate_page);
	set_enqueue_hook(mtat_free_page);

	pebs_start();

	kmonitord = kthread_run(kmonitord_main, NULL, "kmonitord");
	if (IS_ERR(kmonitord)) {
		pr_err("Failed to create kmonitord\n");
	}

	pr_info("Successfully insert MTAT module\n");
	return 0;
}

void cleanup_module(void)
{
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
