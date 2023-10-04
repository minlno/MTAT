#include "mtat.h"
#include "internal.h"

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

bool need_cooling(struct page_list *pl)
{
	bool ret;

	spin_lock(&pl->lock);
	ret = pl->need_cooling;
	spin_unlock(&pl->lock);

	return ret;
}

void set_need_cooling(struct page_list *pl, bool cool)
{
	spin_lock(&pl->lock);
	pl->need_cooling = cool;
	spin_unlock(&pl->lock);
}
struct mtat_page *get_curr_cool_page(struct page_list *pl)
{
	struct mtat_page *m_page = NULL;
	spin_lock(&pl->lock);
	if (!list_empty(&pl->list)) {
		m_page = pl->curr_cool_page;
		if (!m_page)
			m_page = list_first_entry(&pl->list, struct mtat_page, list);
		pl->curr_cool_page = list_next_entry_circular(m_page, &pl->list, list);
	}
	spin_unlock(&pl->lock);

	return m_page;
}

void page_list_del(struct mtat_page *m_page, struct page_list *pl)
{
	spin_lock(&pl->lock);
	if (m_page == pl->curr_cool_page)  {
		pl->curr_cool_page = list_next_entry_circular(m_page, &pl->list, list);
		if (m_page == pl->curr_cool_page)
			pl->curr_cool_page = NULL;
	}
	list_del(&m_page->list);
	pl->num_pages--;
	spin_unlock(&pl->lock);
}

void page_list_add(struct mtat_page *m_page, struct page_list *pl)
{
	spin_lock(&pl->lock);
	list_add_tail(&m_page->list, &pl->list);
	pl->num_pages++;
	spin_unlock(&pl->lock);
}

void init_page_list(struct page_list *pl)
{
	INIT_LIST_HEAD(&pl->list);
	pl->num_pages = 0;
	pl->need_cooling = false;
	pl->curr_cool_page = NULL;
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
 ****************************************
 *  Hashtable for MTAT page management  *
 ****************************************
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
 **********************************
 * kmonitord thread for debugging *
 **********************************
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
 ****************************************
 * PEBS related variables and functions *
 ****************************************
 */
static struct perf_event **events;
static size_t configs[] = { DRAM_READ, PMEM_READ, STORE_ALL };
static struct task_struct *kpebsd;

static __always_inline enum perf_event_state
__perf_effective_state(struct perf_event *event)
{
	struct perf_event *leader = event->group_leader;

	if (leader->state <= PERF_EVENT_STATE_OFF)
		return leader->state;

	return event->state;
}

static __always_inline void
__perf_update_times(struct perf_event *event, u64 now, u64 *enabled, u64 *running)
{
	enum perf_event_state state = __perf_effective_state(event);
	u64 delta = now - event->tstamp;

	*enabled = event->total_time_enabled;
	if (state >= PERF_EVENT_STATE_INACTIVE)
		*enabled += delta;

	*running = event->total_time_running;
	if (state >= PERF_EVENT_STATE_ACTIVE)
		*running += delta;
}

static void perf_event_init_userpage(struct perf_event *event)
{
	struct perf_event_mmap_page *userpg;
	struct perf_buffer *rb;

	rcu_read_lock();
	rb = rcu_dereference(event->rb);
	if (!rb)
		goto unlock;

	userpg = rb->user_page;

	/* Allow new userspace to detect that bit 0 is deprecated */
	userpg->cap_bit0_is_deprecated = 1;
	userpg->size = offsetof(struct perf_event_mmap_page, __reserved);
	userpg->data_offset = PAGE_SIZE;
	userpg->data_size = perf_data_size(rb);

unlock:
	rcu_read_unlock();
}

static void init_perf_buffer(struct perf_event *pe)
{
	struct perf_buffer *rb = NULL;
	unsigned long nr_pages = 1UL << 14;
	unsigned long flags;
	u64 now;

	rb = rb_alloc(nr_pages, 0, pe->cpu, 0);
	if (!rb)
		pr_err("Failed to allocate perf_buffer\n");

	/* ring_buffer_attach() */
	if (pe->rcu_pending) {
		cond_synchronize_rcu(pe->rcu_batches);
		pe->rcu_pending = 0;
	}

	spin_lock_irqsave(&rb->event_lock, flags);
	list_add_rcu(&pe->rb_entry, &rb->event_list);
	spin_unlock_irqrestore(&rb->event_lock, flags);

	//if (has_aux(pe))
	//	perf_event_stop(pe, 0);

	rcu_assign_pointer(pe->rb, rb);

	/* perf_event_update_time() */
	if (!pe->ctx) {
		now = 0;
		pr_err("event->ctx is NULL\n");
	} else {
		now = pe->ctx->time;
	}
	__perf_update_times(pe, now, &pe->total_time_enabled,
			&pe->total_time_running);
	pe->tstamp = now;

	perf_event_init_userpage(pe);
	perf_event_update_userpage(pe);
}

// m_page->lock을 잡고 호출해야함.
static void make_hot_page(struct mtat_page *m_page, int pid_idx, int nid)
{
	m_page->hotness = HOT;
	page_list_del(m_page, &cold_pages[pid_idx][nid]);
	page_list_add(m_page, &hot_pages[pid_idx][nid]);
}

// m_page->lock을 잡고 호출해야함.
static void make_cold_page(struct mtat_page *m_page, int pid_idx, int nid)
{
	m_page->hotness = COLD;
	page_list_del(m_page, &hot_pages[pid_idx][nid]);
	page_list_add(m_page, &cold_pages[pid_idx][nid]);
}

static void partial_cooling_pid(int pid_idx)
{
	int t, i, nid;
	static struct mtat_page *last_page[NR_MEM_TYPES]; 
	struct page_list *pl;
	struct mtat_page *m_page;
	int nr_cooled = 0;

	// cooling fastmem
	for (nid = 0; nid < NR_MEM_TYPES; nid++) {	
		t = COOL_PAGES;
		pl = &hot_pages[pid_idx][nid];

		if (!need_cooling(pl))
			continue;

		while (t--) {
			if (!last_page[nid]) {
				spin_lock(&pl->lock);
				last_page[nid] = list_last_entry(&pl->list, struct mtat_page, list);
				spin_unlock(&pl->lock);
			}

			m_page = get_curr_cool_page(pl);
			if (!m_page)
				break;

			spin_lock(&m_page->lock);

			for (i = 0; i < NR_ACCESS_TYPES; i++) 
				m_page->accesses[i] >>= 
					atomic_read(&global_clock[pid_idx]) - m_page->local_clock;
			m_page->local_clock = atomic_read(&global_clock[pid_idx]);

			if (m_page->accesses[WRITE_MTAT] < HOT_WRITE_THRESHOLD &&
				m_page->accesses[READ_MTAT] < HOT_READ_THRESHOLD) {
				nr_cooled++;
				make_cold_page(m_page, pid_idx, nid);
			}
			
			if (m_page == last_page[nid]) {
				last_page[nid] = NULL;
				set_need_cooling(pl, false);
				spin_unlock(&m_page->lock);
				break;
			}

			spin_unlock(&m_page->lock);
		}
	}
	pr_info("cooled pages: %d\n", nr_cooled);
}

static void partial_cooling(void)
{
	int i;

	for (i = 0; i < MAX_PIDS; i++) {
		if (pids[i] == PID_NONE)
			break;

		partial_cooling_pid(i);
	}
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

static void pebs_sample(uint64_t pfn, int access_type) 
{
	int nid, pid_idx;
	struct mtat_page *m_page = NULL;

	m_page = rhashtable_lookup_fast(hashtable, &pfn, params);
	if (!m_page) {
		return;
	}
	
	spin_lock(&m_page->lock);

	pid_idx = m_page->pids_idx;
	nid = m_page->nid;

	m_page->accesses[access_type] >>= atomic_read(&global_clock[pid_idx]) - m_page->local_clock;
	m_page->local_clock = atomic_read(&global_clock[pid_idx]);

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
		
	if (m_page->accesses[access_type] > COOL_THRESHOLD) {
		atomic_inc(&global_clock[pid_idx]);
		set_need_cooling(&hot_pages[pid_idx][FASTMEM], true);
		set_need_cooling(&hot_pages[pid_idx][SLOWMEM], true);
	}
	
	spin_unlock(&m_page->lock);
}

static int kpebsd_main(void *data)
{
	struct perf_buffer *pe_rb;
	struct perf_event_mmap_page *p;
	struct perf_event_header *ph;
	struct perf_sample *ps;
	char *pbuf;
	size_t idx, config, cpu, ncpus = num_online_cpus();
	int access_type;
	uint64_t pfn;

	pr_info("kpebsd start\n");
	while (!kthread_should_stop()) {
		for (config = 0; config < ARRAY_SIZE(configs); config++) {
			for (cpu = 0; cpu < ncpus; cpu++) {
				idx = config * ncpus + cpu;
				pe_rb = events[idx]->rb;
				if (!pe_rb) {
					pr_info("CPU%lu: rb is NULL\n", cpu);
					continue;
				}
				p = pe_rb->user_page;
				pbuf = (char *)p + p->data_offset;

				smp_rmb();

				if (p->data_head == p->data_tail)
					continue;

				ph = (void *)(pbuf + (p->data_tail % p->data_size));

				switch (ph->type) {
				case PERF_RECORD_SAMPLE:
					ps = (struct perf_sample *)ph;
					if (!ps) {
						pr_err("ps is NULL\n");
						continue;
					}

					//pfn = perf_virt_to_phys(ps->addr) >> HPAGE_SHIFT;
					pfn = ps->phys_addr >> HPAGE_SHIFT;
					access_type = configs[config] == STORE_ALL ? WRITE_MTAT : READ_MTAT;
					pebs_sample(pfn, access_type);
					break;
				}
				p->data_tail += ph->size;
			}
		}

		if (need_resched())
			schedule();
	}

	pr_info("kpebsd exit\n");
	return 0;
}

static void pebs_start(void)
{
	size_t idx, config, cpu, ncpus = num_online_cpus();
	static struct perf_event_attr wd_hw_attr = {
		.type = PERF_TYPE_RAW,
		.size = sizeof(struct perf_event_attr),
		//.pinned = 0,
		.disabled = 0,
		.precise_ip = 2,
		.sample_id_all = 1,
		.exclude_kernel = 1,
		.exclude_guest = 1,
		.exclude_hv = 1,
		.exclude_callchain_kernel = 1,
		.exclude_callchain_user = 1,
		.exclude_user = 0,
		.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_PHYS_ADDR,
	};

	events = vmalloc(ncpus * ARRAY_SIZE(configs) * sizeof(*events));
	if (!events) {
		pr_err("Failed to allocate perf_event\n");
		return;
	}

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			idx = config * ncpus + cpu;
			wd_hw_attr.config = configs[config];
			wd_hw_attr.sample_period = SAMPLE_PERIOD_PEBS;
			events[idx] = 
				perf_event_create_kernel_counter(&wd_hw_attr,
						cpu, NULL, NULL, NULL);
			if (IS_ERR(events[idx])) {
				pr_err("Failed to create event %lu on cpu %lu\n", configs[config], cpu);
				return;
			}
			init_perf_buffer(events[idx]);
			perf_event_enable(events[idx]);
		}
	}

	kpebsd = kthread_run(kpebsd_main, NULL, "kpebsd");
	if (IS_ERR(kpebsd))
		pr_err("Failed to create kpebsd\n");
}
static void pebs_stop(void)
{
	size_t idx, config, cpu, ncpus = num_online_cpus();

	if (kpebsd)
		kthread_stop(kpebsd);

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			idx = config * ncpus + cpu;
			perf_event_disable(events[idx]);
			ring_buffer_put(events[idx]->rb);
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
	page_list_add(m_page, &f_pages[nid]);
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
		page_list_del(m_page, &hot_pages[m_page->pids_idx][m_page->nid]);
	else
		page_list_del(m_page, &cold_pages[m_page->pids_idx][m_page->nid]);
	page_list_add(m_page, &f_pages[m_page->nid]);

	spin_unlock(&m_page->lock);

	return 0;
}

static void build_page_list(void)
{
	int i, j, nid, nb_pages = 0;
	struct hstate *h;
	struct page *page;

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

	if (MTAT_MIGRATION_MODE == HEMEM) {
		i = 0;
		pids[0] = 0;
		goto m_page_init;
	}

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

m_page_init:
	spin_lock(&m_page->lock);

	m_page->local_clock = atomic_read(&global_clock[i]);
	m_page->hotness = COLD;
	m_page->pids_idx = i;
	m_page->nid = nid;
	memset(m_page->accesses, 0, sizeof(m_page->accesses));
	page_list_del(m_page, &f_pages[nid]);
	page_list_add(m_page, &cold_pages[i][nid]);

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

static unsigned int migrate_page_list(struct list_head *page_list, int nid, int pid)
{
	unsigned int nr_migrated_pages = 0;
	struct page *page;
	struct page *page2;

	struct migration_target_control mtc = {
		.nid = nid,
		.pid = pid
	};

	if (list_empty(page_list))
		return 0;

	if (migrate_pages(page_list, mtat_alloc_migration_target,
				NULL, (unsigned long)&mtc, MIGRATE_SYNC,
				MR_NUMA_MISPLACED, &nr_migrated_pages)) {
		pr_err("migration partially failed.\n");
		list_for_each_entry_safe(page, page2, page_list, lru) {
			putback_active_hugepage(page);
		}
	}

	return nr_migrated_pages;
}

static unsigned int isolate_mtat_pages(struct page_list *from, 
		struct list_head *to, int target_nr)
{
	struct mtat_page *m_page = NULL;
	int nr = 0;

	spin_lock(&from->lock);
	list_for_each_entry(m_page, &from->list, list) {
		if (nr >= target_nr)
			break;
		if (isolate_hugetlb(m_page->page, to))
			continue;
		nr++;
	}
	spin_unlock(&from->lock);

	return nr;
}

static void solorun_migration(void)
{
	LIST_HEAD(promote_pages);
	LIST_HEAD(demote_pages);
	int nr_fmem_free, nr_fmem_cold;
	int target_promote, target_demote; 
	int nr_promote, nr_demote;

	pr_info("%s\n", __func__);

	nr_fmem_free = get_num_pages(&f_pages[FASTMEM]);
	nr_fmem_cold = get_num_pages(&cold_pages[0][FASTMEM]);
	target_promote = min(nr_fmem_free + nr_fmem_cold, get_num_pages(&hot_pages[0][SLOWMEM]));
	target_demote = max(0, target_promote - nr_fmem_free);
	if (WARM_SET_SIZE >= 0 && 
		nr_fmem_cold - target_demote > WARM_SET_SIZE)
		target_demote = nr_fmem_cold - WARM_SET_SIZE;

	nr_promote = isolate_mtat_pages(&hot_pages[0][SLOWMEM], &promote_pages, target_promote);
	nr_demote = isolate_mtat_pages(&cold_pages[0][FASTMEM], &demote_pages, target_demote);

	pr_info("Expected demoted pages: %u\n", nr_demote);
	pr_info("Expected promoted pages: %u\n", nr_promote);

	nr_demote = migrate_page_list(&demote_pages, SLOWMEM, pids[0]);
	nr_promote = migrate_page_list(&promote_pages, FASTMEM, pids[0]);

	pr_info("Real demoted pages: %u\n", nr_demote/512);
	pr_info("Real promoted pages: %u\n", nr_promote/512);
}

/*
 * LC: pids[0], BE: pids[1]
 * LC hot page는 모두 FMEM에 이주
 * LC FMEM cold page는 warm set size 만큼만 남기고 나머지 다 SMEM에 이주
 * FMEM이 남으면 BE의 SMEM page들을 FMEM에 이주 (hot page를 우선적으로)
 */
static void corun_migration(void)
{
	struct list_head promote_pages[2]; // [lc/be]
	struct list_head demote_pages[2]; // [lc/be]
	const int lc = 0, be = 1;
	int nr_fmem_free;
	int nr_fmem_hot[2], nr_fmem_cold[2]; // [lc/be]
	int nr_smem_hot[2], nr_smem_cold[2]; // [lc/be]
	int target_promote[2][2], target_demote[2][2]; // [lc/be][HOT/COLD]
	int nr_promote[2], nr_demote[2]; // [lc/be]
	int i, j;
	pr_info("%s\n", __func__);

	for (i = 0; i < 2; i++) {
		for (j = 0; j < 2; j++) {
			target_promote[i][j] = 0;
			target_demote[i][j] = 0;
		}
		INIT_LIST_HEAD(&promote_pages[i]);
		INIT_LIST_HEAD(&demote_pages[i]);
	}

	nr_fmem_free = get_num_pages(&f_pages[FASTMEM]);
	for (i = 0; i < 2; i++) {
		nr_fmem_hot[i] = get_num_pages(&hot_pages[i][FASTMEM]);
		nr_fmem_cold[i] = get_num_pages(&cold_pages[i][FASTMEM]);
		nr_smem_hot[i] = get_num_pages(&hot_pages[i][SLOWMEM]);
		nr_smem_cold[i] = get_num_pages(&cold_pages[i][SLOWMEM]);
	}

	/* Calculate target_promote, target_demote size for LC */
	target_promote[lc][HOT] = min(nr_fmem_free + nr_fmem_cold[lc] + nr_fmem_cold[be],
				get_num_pages(&hot_pages[lc][SLOWMEM]));
	target_demote[lc][COLD] = max(0, target_promote[lc][HOT] - nr_fmem_free - nr_fmem_cold[be]);
	if (WARM_SET_SIZE >= 0) {
		int lc_remain_cold = nr_fmem_cold[lc] - target_demote[lc][COLD];
		if (lc_remain_cold > WARM_SET_SIZE) {
			target_demote[lc][COLD] = nr_fmem_cold[lc] - WARM_SET_SIZE;
		} else if (lc_remain_cold < WARM_SET_SIZE) {
			int leftover = WARM_SET_SIZE - lc_remain_cold;
			if (leftover <= target_demote[lc][COLD])
				target_demote[lc][COLD] -= leftover;
			else {
				target_promote[lc][COLD] = target_demote[lc][COLD] + leftover;
				target_demote[lc][COLD] = 0;
			}
		}
	}

	/* Calculate target_promote, target_demote size for BE */
	int be_fmem_size = nr_fmem_free + nr_fmem_hot[be] + nr_fmem_cold[be];
	int fmem_for_be = be_fmem_size - target_promote[lc][HOT] 
		- target_promote[lc][COLD] + target_demote[lc][COLD];
	if (be_fmem_size > fmem_for_be) {
		int leftover = be_fmem_size - fmem_for_be;
		target_demote[be][COLD] = min(leftover, nr_fmem_cold[be]);
		target_promote[be][HOT] = max(0, leftover - target_demote[be][COLD]);
	} else if (be_fmem_size < fmem_for_be) {
		int leftover = fmem_for_be - be_fmem_size;
		target_promote[be][HOT] = min(leftover, nr_smem_hot[be]);
		target_promote[be][COLD] = max(0, leftover - target_promote[be][HOT]);
	}

	/* Isolate pages for migration */
	for (i = 0; i < 2; i++) {
		nr_promote[i] = isolate_mtat_pages(&hot_pages[i][SLOWMEM], 
					&promote_pages[i], target_promote[i][HOT]);
		nr_promote[i] += isolate_mtat_pages(&cold_pages[i][SLOWMEM], 
					&promote_pages[i], target_promote[i][COLD]);
		nr_demote[i] = isolate_mtat_pages(&hot_pages[i][FASTMEM], 
					&demote_pages[i], target_demote[i][HOT]);
		nr_demote[i] += isolate_mtat_pages(&cold_pages[i][FASTMEM], 
					&demote_pages[i], target_demote[i][COLD]);
	}

	/* Do Migration */
	pr_info("LC - Expected demoted pages: %u\n", nr_demote[lc]);
	pr_info("LC - Expected promoted pages: %u\n", nr_promote[lc]);
	pr_info("BE - Expected demoted pages: %u\n", nr_demote[be]);
	pr_info("BE - Expected promoted pages: %u\n", nr_promote[be]);

	nr_demote[be] = migrate_page_list(&demote_pages[be], SLOWMEM, pids[be]);
	nr_demote[lc] = migrate_page_list(&demote_pages[lc], SLOWMEM, pids[lc]);
	nr_promote[lc] = migrate_page_list(&promote_pages[lc], FASTMEM, pids[lc]);
	nr_promote[be] = migrate_page_list(&promote_pages[be], FASTMEM, pids[be]);

	pr_info("LC - Real demoted pages: %u\n", nr_demote[lc]/512);
	pr_info("LC - Real promoted pages: %u\n", nr_promote[lc]/512);
	pr_info("BE - Real demoted pages: %u\n", nr_demote[be]/512);
	pr_info("BE - Real promoted pages: %u\n", nr_promote[be]/512);
}

static void hemem_migration(void)
{
	LIST_HEAD(promote_pages);
	LIST_HEAD(demote_pages);
	int nr_fmem_free, nr_fmem_cold;
	int target_promote, target_demote; 
	int nr_promote, nr_demote;

	pr_info("%s\n", __func__);

	nr_fmem_free = get_num_pages(&f_pages[FASTMEM]);
	nr_fmem_cold = get_num_pages(&cold_pages[0][FASTMEM]);
	target_promote = min(nr_fmem_free + nr_fmem_cold, get_num_pages(&hot_pages[0][SLOWMEM]));
	target_demote = max(0, target_promote - nr_fmem_free);

	nr_promote = isolate_mtat_pages(&hot_pages[0][SLOWMEM], &promote_pages, target_promote);
	nr_demote = isolate_mtat_pages(&cold_pages[0][FASTMEM], &demote_pages, target_demote);

	pr_info("Expected demoted pages: %u\n", nr_demote);
	pr_info("Expected promoted pages: %u\n", nr_promote);

	nr_demote = migrate_page_list(&demote_pages, SLOWMEM, pids[0]);
	nr_promote = migrate_page_list(&promote_pages, FASTMEM, pids[0]);

	pr_info("Real demoted pages: %u\n", nr_demote/512);
	pr_info("Real promoted pages: %u\n", nr_promote/512);
}

static void test_migration(void)
{
	LIST_HEAD(folio_list);
	unsigned int nr_pages;
	struct mtat_page *m_page = NULL;
	struct migration_target_control mtc;
	int nid;

	pr_info("%s\n", __func__);

	nid = SLOWMEM;
	nr_pages = 0;
	spin_lock(&cold_pages[0][FASTMEM].lock);
	list_for_each_entry(m_page, &cold_pages[0][FASTMEM].list, list) {
		if (isolate_hugetlb(m_page->page, &folio_list))
			continue;
		nr_pages++;
	}
	spin_unlock(&cold_pages[0][FASTMEM].lock);

	if (nr_pages > 0)
		goto migrate;

	nid = FASTMEM;
	spin_lock(&cold_pages[0][SLOWMEM].lock);
	list_for_each_entry(m_page, &cold_pages[0][SLOWMEM].list, list) {
		if (isolate_hugetlb(m_page->page, &folio_list))
			continue;
		nr_pages++;
	}
	spin_unlock(&cold_pages[0][SLOWMEM].lock);

migrate:
	pr_info("Expected migrated pages: %u\n", nr_pages);
	mtc.nid = nid;
	mtc.pid = pids[0];
	migrate_pages(&folio_list, mtat_alloc_migration_target,
				NULL, (unsigned long)&mtc, MIGRATE_SYNC,
				MR_NUMA_MISPLACED, &nr_pages);
	pr_info("Real migrated pages: %u\n", nr_pages/512);
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
		if (migrate_on) {
			do_migration();
		}
		partial_cooling();
		ssleep(5);
	}
	pr_info("kmigrated exit\n");
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
