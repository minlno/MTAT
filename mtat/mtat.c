#include "mtat.h"
#include "internal.h"
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>

#ifdef CXL_MODE
static int memory_nodes[] = {0, 1};
#else
static int memory_nodes[] = {0, 2};
#endif
static int FASTMEM;
static int SLOWMEM;
#define NR_MEM_TYPES 3

// ms, cooling_period는 mtat manager의 정책 결정 주기와 동일해야함.
static unsigned long cooling_period = 1000; 
static unsigned long mtat_migration_period = 1; // ms
static unsigned long min_hot_threshold = 1;

/*
 * Sysfs parameters
 */
struct mtat_sysfs_ui_dir *mtat_sysfs;
static int mtat_sysfs_apps_dir_add_dirs(struct mtat_sysfs_apps_dir *apps_dir, int app_idx);
static int mtat_sysfs_app_dir_add_dirs(struct mtat_sysfs_apps_dir *apps_dir, int pids_idx);
static unsigned long migrate_on = 0;
static unsigned long pebs_on = 1;
static unsigned long mtat_debug_on = 1;
static unsigned long total_dram_pages = 0; // 2MB pages

/*
 * app_struct related variables
 */
static struct app_struct apps[MAX_APPS];

/*
 * Page list related variables
 *
 * lock 규칙:
 * - list_del, list_add 모두 mtat_page->lock,  page_list->lock 잡은 후 수행.
 *
 * lock 순서:
 * total_pages_lock
 *  mtat_page->lock
 *   app->lock, hg->lock, debug->lock, mtat_pages->lock
 */
static struct list_head total_pages[MAX_APPS]; // for cooling
static spinlock_t total_pages_lock[MAX_APPS];
static struct page_list f_pages[NR_MEM_TYPES]; // free_pages
static struct page_list mtat_pages[NR_HOTNESS_TYPES][MAX_APPS][NR_MEM_TYPES];

/*
 * Hashtable for mtat_page management
 */
static struct rhashtable *hashtable = NULL;
static struct rhashtable_params params = {
	.head_offset = offsetof(struct mtat_page, node),
	.key_offset = offsetof(struct mtat_page, pfn),
	.key_len = sizeof(uint64_t),
	.automatic_shrinking = false,
	.min_size = 0xffff,
};

static struct task_struct *kdebugd;
static struct task_struct *kpebsd;
static struct task_struct *kmigrated;
static struct task_struct *kcoolingd;

static struct perf_event ***events;
static int **events_fd;

#ifdef CXL_MODE
static size_t configs[] = { DRAM_READ, CXL_READ, STORE_ALL };
#else
static size_t configs[] = { DRAM_READ, PMEM_READ, STORE_ALL };
#endif

static size_t cpus[] = {16,17,18,19,20,21,22,23,
					   48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
					   64,65,66,67,68,69,70,71};
//static size_t cpus[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,
//					   48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71};
//static size_t cpus[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23};
//static size_t cpus[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,
//						25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48};

/*
 * Util funtions
 */
static void mtat_set_cpu_affinity(int cpu)
{
	struct cpumask *mask;

	mask = kzalloc(sizeof(struct cpumask), GFP_KERNEL);
	if (!mask) {
		pr_err("Failed to allocate memory for cpumask\n");
		return;
	}

	cpumask_clear(mask);
	cpumask_set_cpu(cpu, mask);

	set_cpus_allowed_ptr(current, mask);

	kfree(mask);
}

static uint64_t perf_virt_to_phys(u64 virt, pid_t pid)
{
	uint64_t phys_addr = 0;
	struct task_struct *tsk;
	struct pid *pid_struct;

	pid_struct = find_get_pid(pid);
	if (!pid_struct) {
		//pr_info("pid: %u\n", pid);
		//pr_info("no pid struct\n");
		return 0;
	}

	tsk = pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);

	if (!tsk) {
		//pr_info("no tsk struct\n");
		return 0;
	}

	if (!virt)
		return 0;

	if (virt >= TASK_SIZE) {
		if (virt_addr_valid((void *)(uintptr_t)virt) &&
		    !(virt >= VMALLOC_START && virt < VMALLOC_END))
			phys_addr = (uint64_t)virt_to_phys((void *)(uintptr_t)virt);
	} else {
		if (tsk->mm != NULL) {
			struct page *p;
			pagefault_disable();
			if (get_user_pages_remote(tsk->mm, virt, 1, 0, &p, NULL, NULL)) {
				if (p) {
					phys_addr = (page_to_pfn(p) << PAGE_SHIFT);
					//phys_addr = (page_to_pfn(p) << PAGE_SHIFT) + virt % PAGE_SIZE;
					put_page(p);
				}
			}
			pagefault_enable();
		}
	}
	return phys_addr;
}

/*
 * Access Histogram
 */
static void init_hg(struct access_histogram *hg)
{
	hg->hot_threshold = min_hot_threshold;
	hg->warm_threshold = min_hot_threshold - 1;
	spin_lock_init(&hg->lock);
}

static uint64_t hg_get_idx(uint64_t num)
{
	uint64_t cnt = 0;

	num++;
	while (1) {
		num = num >> 1;
		if (num)
			cnt++;
		else return cnt;

		if (cnt == 15)
			break;
	}
	return cnt;
}

static uint64_t hg_get_accesses(uint64_t idx)
{
	uint64_t accesses = 1;
	if (!idx) return 0;
	while (--idx)
		accesses <<= 1;
	return accesses;
}

static void hg_update_hot_threshold(struct access_histogram *hg, uint64_t dram_size)
{
	uint64_t tmp = 0;
	int i;

	spin_lock(&hg->lock);
	for (i = 15; i >= 0; i--) {
		tmp += hg->histogram[i];
		if (tmp > dram_size) {
			hg->hot_threshold = i+1;
			hg->warm_threshold = i;
			spin_unlock(&hg->lock);
			return;
		}
	}
	hg->hot_threshold = min_hot_threshold;
	hg->warm_threshold = min_hot_threshold - 1;
	spin_unlock(&hg->lock);
}

/*
 * app_struct related functions
 */
static void init_debug(struct mtat_debug_info *debug)
{
	spin_lock_init(&debug->lock);
}

static void init_apps(void)
{
	int i, j;

	for (i = 0; i < MAX_APPS; i++) {
		apps[i].pid = PID_NONE;
		spin_lock_init(&apps[i].lock);

		init_debug(&apps[i].debug);
		init_hg(&apps[i].hg);
		for (j = 0; j < MAX_APPS; j++) {
			apps[i]._pids[j] = PID_NONE;
		}
	}
}

/*
 * Page list related functions
 *
 * lock 규칙:
 * - list_del, list_add 모두 mtat_page->lock,  page_list->lock 잡은 후 수행.
 *
 * lock 순서:
 * total_pages_lock
 *  mtat_page->lock
 *   app->lock, mtat_pages->lock, lock
 */
struct mtat_page *alloc_and_init_mtat_page(struct page *page)
{
	struct mtat_page *m_page = kmalloc(sizeof(*m_page), GFP_KERNEL);

	if (!m_page)
		return NULL;

	m_page->page = page;
	m_page->pfn = page_to_pfn(page) << PAGE_SHIFT >> HPAGE_SHIFT;
	m_page->accesses = 0;
	m_page->hotness = COLD;
	m_page->apps_idx = PID_NONE;
	m_page->nid = page_to_nid(page);
	m_page->hg_idx = 0;
	INIT_LIST_HEAD(&m_page->list);
	INIT_LIST_HEAD(&m_page->t_list);
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

int get_num_pages_pid(struct page_list *pl, int pids_idx)
{
	int num_pages;

	spin_lock(&pl->lock);
	num_pages = pl->num_pages_pid[pids_idx];
	spin_unlock(&pl->lock);

	return num_pages;
}

void page_list_del(struct mtat_page *m_page, struct page_list *pl)
{
	int pids_idx = m_page->pids_idx;

	spin_lock(&pl->lock);
	list_del(&m_page->list);
	pl->num_pages--;
	if (MTAT_MIGRATION_MODE != MTAT) 
		pl->num_pages_pid[pids_idx]--;
	spin_unlock(&pl->lock);
}

void page_list_add(struct mtat_page *m_page, struct page_list *pl)
{
	int pids_idx = m_page->pids_idx;

	spin_lock(&pl->lock);
	list_add_tail(&m_page->list, &pl->list);
	pl->num_pages++;
	if (MTAT_MIGRATION_MODE != MTAT) 
		pl->num_pages_pid[pids_idx]++;
	spin_unlock(&pl->lock);
}

void init_page_list(struct page_list *pl)
{
	int i;
	INIT_LIST_HEAD(&pl->list);
	pl->num_pages = 0;
	for (i = 0; i < MAX_APPS; i++)
		pl->num_pages_pid[i] = 0;
	spin_lock_init(&pl->lock);
}

/*
 ****************************************
 *  Hashtable for MTAT page management  *
 ****************************************
 */
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
 * kdebugd thread for debugging *
 **********************************
 */
static void print_debug(struct mtat_debug_info *debug)
{
	uint64_t total_sampled = 0;
	int i;

	// Lock 굳이 안잡음. 어차피 눈으로 확인하는 용도라서 값이 좀 틀려도 상관없음.
	for (i = 0; i < 4; i++)
		total_sampled += debug->nr_sampled[i];
	pr_info("total_sampled: %llu\n", total_sampled);
	pr_info("----DRAM_READ: %llu\n", debug->nr_sampled[0]);
#ifdef CXL_MODE
	pr_info("----CXL_READ: %llu\n", debug->nr_sampled[2]);
#else
	pr_info("----PMEM_READ: %llu\n", debug->nr_sampled[1]);
#endif
	pr_info("----STORE_ALL: %llu\n", debug->nr_sampled[3]);
	pr_info("nr_cooled: %llu\n", debug->nr_cooled);
	pr_info("nr_migrated: %llu MB\n", debug->nr_migrated);
}

static void print_debug_stats(void)
{
	struct app_struct *app;
	struct mtat_debug_info *debug;
	int i, j;

	pr_info("=======================================\n");
	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE)
			break;
		pr_info("pid: %d\n", app->pid);
		debug = &app->debug;
		for (j = 0; j < NR_MEM_TYPES; j++) {
			if (j != memory_nodes[0] && j != memory_nodes[1])
				continue;
			pr_info("--numa node: %d, free_pages: %d\n", j, get_num_pages(&f_pages[j]));
			pr_info("----hot_pages: %d\n", get_num_pages(&mtat_pages[HOT][i][j]));
			pr_info("----warm_pages: %d\n", get_num_pages(&mtat_pages[WARM][i][j]));
			pr_info("----cold_pages: %d\n", get_num_pages(&mtat_pages[COLD][i][j]));
		}
		print_debug(debug);
	}
}

static void update_debug_stats(void)
{
	struct app_struct *app;
	struct mtat_debug_info *debug;
	int i, j;
	int nr_total_sampled, nr_fmem_read, nr_smem_read;
	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE) {
			break;
		}
		debug = &app->debug;

		nr_total_sampled = 0;
		nr_fmem_read = 0;
		nr_smem_read = 0;

		spin_lock(&debug->lock);
		for (j = 0; j < 4; j++)
			nr_total_sampled += debug->nr_sampled[j];
		nr_fmem_read = debug->nr_sampled[0];
		nr_smem_read = debug->nr_sampled[1] + debug->nr_sampled[2];
		spin_unlock(&debug->lock);

		spin_lock(&app->lock);
		app->nr_total_sampled = nr_total_sampled;
		app->nr_fmem_read = nr_fmem_read;
		app->nr_smem_read = nr_smem_read;
		spin_unlock(&app->lock);
	}

}

static void clear_debug_stats(void)
{
	struct app_struct *app;
	struct mtat_debug_info *debug;
	int i, j;
	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE) {
			break;
		}
		debug = &app->debug;

		spin_lock(&debug->lock);
		for (j = 0; j < 4; j++)
			debug->nr_sampled[j] = 0;
		debug->nr_cooled = 0;
		debug->nr_migrated = 0;
		spin_unlock(&debug->lock);
	}
}

static int kdebugd_main(void *data)
{
	pr_info("kdebugd start\n");

	mtat_set_cpu_affinity(KDEBUGD_CPU);

	while (!kthread_should_stop()) {
		if (mtat_debug_on) {
			print_debug_stats();
			update_debug_stats();
			clear_debug_stats();
		}

		msleep(cooling_period);
	}

	pr_info("kdebugd exit\n");

	return 0;
}

/*
 ****************************************
 * PEBS related variables and functions *
 ****************************************
 */

// m_page->lock을 잡고 호출해야함.
// app->lock도 필요
static bool is_hot_page(struct mtat_page *m_page, uint64_t hot_threshold)
{
	uint64_t hot_access;

	hot_access = hg_get_accesses(hot_threshold);

	if (m_page->accesses >= hot_access)
		return true;
	else 
		return false;
}

// m_page->lock 필요
// app->lock도 필요
// hot도 true로 뱉음
static bool is_warm_page(struct mtat_page *m_page, uint64_t warm_threshold)
{
	uint64_t warm_access;
	warm_access = hg_get_accesses(warm_threshold);

	if (m_page->accesses >= warm_access)
		return true;
	else 
		return false;

}

// m_page->lock 필요
// hg->lock은 잡으면 안됨.
static void update_page_list_with_mpage(struct mtat_page *m_page)
{
	int prev_hotness = m_page->hotness;
	int cur_hotness;
	int app_idx = m_page->apps_idx;
	int nid = m_page->nid;
	struct app_struct *app = &apps[app_idx];
	struct access_histogram *hg = &app->hg;
	

	spin_lock(&hg->lock);
	if (is_hot_page(m_page, hg->hot_threshold))
		cur_hotness = HOT;
	else if (is_warm_page(m_page, hg->warm_threshold))
		cur_hotness = WARM;
	else
		cur_hotness = COLD;
	spin_unlock(&hg->lock);

	if (prev_hotness == cur_hotness)
		return;

	m_page->hotness = cur_hotness;
	page_list_del(m_page, &mtat_pages[prev_hotness][app_idx][nid]);
	page_list_add(m_page, &mtat_pages[cur_hotness][app_idx][nid]);
}

static void periodic_cooling_pid(int app_idx)
{
	struct mtat_page *m_page;
	struct app_struct *app = &apps[app_idx];
	struct access_histogram *hg = &app->hg;
	struct mtat_debug_info *debug = &app->debug;
	int nr_cooled = 0;
	int cur_access, prev_idx, cur_idx;

	spin_lock(&total_pages_lock[app_idx]);
	list_for_each_entry(m_page, &total_pages[app_idx], t_list) {
		spin_lock(&m_page->lock);

		// 접근횟수 cooling
		m_page->accesses >>= 1;

		// 쿨링 후 필요하면 cold list로 보내기
		update_page_list_with_mpage(m_page);

		// 히스토그램 인덱스 계산
		prev_idx = m_page->hg_idx;
		cur_access = m_page->accesses;
		cur_idx = hg_get_idx(cur_access);
		m_page->hg_idx = cur_idx;

		// 쿨링 후 히스토그램 카운터 관리
		spin_lock(&hg->lock);

		hg->histogram[prev_idx]--;
		hg->histogram[cur_idx]++;

		spin_unlock(&hg->lock);
		spin_unlock(&m_page->lock);

		nr_cooled++;
	}
	spin_unlock(&total_pages_lock[app_idx]);

	spin_lock(&debug->lock);
	debug->nr_cooled += nr_cooled;
	spin_unlock(&debug->lock);
}

static void periodic_cooling(void)
{
	int i;
	struct app_struct *app;

	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE) {
			break;
		}

		periodic_cooling_pid(i);
	}
}

static void pebs_sample(uint64_t pfn, size_t config) 
{
	int nid, app_idx;
	struct mtat_page *m_page = NULL;
	struct app_struct *app;
	struct access_histogram *hg;
	struct mtat_debug_info *debug;
	uint64_t cur_access, prev_idx, cur_idx;

	m_page = rhashtable_lookup_fast(hashtable, &pfn, params);
	if (!m_page) {
		return;
	}
	
	app_idx = m_page->apps_idx;
	nid = m_page->nid;

	app = &apps[app_idx];
	debug = &app->debug;
	hg = &app->hg;

	spin_lock(&debug->lock);
	if (configs[config] == DRAM_READ)
		debug->nr_sampled[0]++;
	else if (configs[config] == PMEM_READ)
		debug->nr_sampled[1]++;
	else if (configs[config] == CXL_READ)
		debug->nr_sampled[2]++;
	else
		debug->nr_sampled[3]++;
	spin_unlock(&debug->lock);

	spin_lock(&m_page->lock);

	// 접근횟수 카운팅
	m_page->accesses++;

	// 히스토그램 관련 인덱스 계산
	prev_idx = m_page->hg_idx;
	cur_access = m_page->accesses;
	cur_idx = hg_get_idx(cur_access);
	m_page->hg_idx = cur_idx;

	// m_page hot, warm, cold list 관리
	update_page_list_with_mpage(m_page);

	// 히스토그램 카운터 관리
	spin_lock(&hg->lock);

	hg->histogram[prev_idx]--;
	hg->histogram[cur_idx]++;

	spin_unlock(&hg->lock);
	spin_unlock(&m_page->lock);
}

static void pebs_restart(void);
static int kpebsd_main(void *data)
{
	struct perf_buffer *pe_rb;
	struct perf_event_mmap_page *p;
	struct perf_event_header *ph;
	struct perf_sample *ps;
	size_t config, cpu, i;
	uint64_t pfn, pg_index, offset;
	int page_shift;
	unsigned long prev_jiff, delay = 1800 * HZ;

	pr_info("kpebsd start\n");

	mtat_set_cpu_affinity(KPEBSD_CPU);

	prev_jiff = jiffies;
	while (!kthread_should_stop()) {
		if (!pebs_on) {
			pebs_restart();
			msleep(5000);
			continue;
		}

		if (time_after(jiffies, prev_jiff + delay)) {
			pebs_restart();
			pr_info("pebs_restart\n");
			prev_jiff = jiffies;
		}

		for (config = 0; config < ARRAY_SIZE(configs); config++) {
			for (i = 0; i < ARRAY_SIZE(cpus); i++) {
				cpu = cpus[i];

				__sync_synchronize();

				pe_rb = events[i][config]->rb;
				if (!pe_rb) {
					pr_info("CPU%lu: rb is NULL\n", cpu);
					continue;
				}
				p = READ_ONCE(pe_rb->user_page);
				if (READ_ONCE(p->data_head) == READ_ONCE(p->data_tail)) {
					continue;
				}

				smp_rmb();

				page_shift = PAGE_SHIFT + page_order(pe_rb);
				offset = READ_ONCE(p->data_tail);
				pg_index = (offset >> page_shift) & (pe_rb->nr_pages - 1);
				offset &= (1 << page_shift) - 1;

				ph = (void*)(pe_rb->data_pages[pg_index] + offset);

				switch (ph->type) {
				case PERF_RECORD_SAMPLE:
					ps = (struct perf_sample *)ph;
					if (!ps) {
						pr_err("ps is NULL\n");
						break;
					}
					
					if (cpu != ps->cpu) {
						//pr_info("current v.s. sample: %lu, %u\n", cpu, ps->cpu);
						break;
					}

					pfn = perf_virt_to_phys(ps->addr, ps->pid) >> HPAGE_SHIFT;
					pebs_sample(pfn, config);
					break;
				case PERF_RECORD_THROTTLE:
				case PERF_RECORD_UNTHROTTLE:
					break;
				case PERF_RECORD_LOST_SAMPLES:
					break;
				}
				smp_mb();
				WRITE_ONCE(p->data_tail, p->data_tail + ph->size);
			}
		}
		if (need_resched())
			schedule();
	}

	pr_info("kpebsd exit\n");
	return 0;
}

static int __perf_event_open(u64 cpu_idx, u64 config)
{
	struct perf_event_attr attr;
	struct file *file;
	int event_fd;

	memset(&attr, 0, sizeof(struct perf_event_attr));

	attr.type = PERF_TYPE_RAW;
	attr.size = sizeof(struct perf_event_attr);
	attr.config = configs[config];
	attr.config1 = 0;
	attr.sample_period = SAMPLE_PERIOD_PEBS;
	attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU;
	attr.disabled = 0;
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.exclude_callchain_kernel = 1;
	attr.exclude_callchain_user = 1;
	attr.precise_ip = 1;
	attr.enable_on_exec = 1;

	event_fd = mtat__perf_event_open(&attr, -1, cpus[cpu_idx], -1, 0);
	if (event_fd <= 0) {
		pr_err("mtat__perf_event_open failed, event_fd: %d\n", event_fd);
		return -1;
	}

	file = fget(event_fd);
	if (!file) {
		pr_err("invalid file\n");
		return -1;
	}
	events[cpu_idx][config] = fget(event_fd)->private_data;
	events_fd[cpu_idx][config] = event_fd;
	return 0;
}

static void pebs_restart(void)
{
	size_t config, cpu, ncpus = ARRAY_SIZE(cpus);

	/* perf_event_disable + perf_event_open
	 * 
	 * disable 후에 file, fd 정리하고 다시 오픈해야함
	 */
	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			perf_event_disable(events[cpu][config]);
		}
	}
	msleep(100);
	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			put_unused_fd(events_fd[cpu][config]);
		}
	}
	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			if (__perf_event_open(cpu, config)) {
				pr_err("Failed to open perf_event\n");
				return;
			}
			if (mtat__perf_event_init(events[cpu][config], 128)) {
				pr_err("Failed to init perf_event\n");
				return;
			}

		}
	}
}

static void pebs_start(void)
{
	size_t config, cpu;

	events = kzalloc(sizeof(struct perf_event **) * ARRAY_SIZE(cpus), GFP_KERNEL);
	events_fd = kzalloc(sizeof(int *) * ARRAY_SIZE(cpus), GFP_KERNEL);
	for (cpu = 0; cpu < ARRAY_SIZE(cpus); cpu++) {
		events[cpu] = kzalloc(sizeof(struct perf_event *) * ARRAY_SIZE(configs), GFP_KERNEL);
		events_fd[cpu] = kzalloc(sizeof(int) * ARRAY_SIZE(configs), GFP_KERNEL);
	}

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ARRAY_SIZE(cpus); cpu++) {
			if (__perf_event_open(cpu, config)) {
				pr_err("Failed to open perf_event\n");
				return;
			}
			if (mtat__perf_event_init(events[cpu][config], 1024)) {
				pr_err("Failed to init perf_event\n");
				return;
			}
			//perf_event_enable(events[cpu][config]);
		}
	}

	kpebsd = kthread_run(kpebsd_main, NULL, "kpebsd");
	if (IS_ERR(kpebsd))
		pr_err("Failed to create kpebsd\n");

	return;
}

static void pebs_stop(void)
{
	size_t config, cpu, ncpus = ARRAY_SIZE(cpus);

	if (kpebsd)
		kthread_stop(kpebsd);

	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			perf_event_disable(events[cpu][config]);
		}
	}

	for (cpu = 0; cpu < ARRAY_SIZE(cpus); cpu++)
		kfree(events[cpu]);
	kfree(events);
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
	int hg_idx;
	int app_idx;
	struct mtat_page *m_page = rhashtable_lookup_fast(hashtable, &pfn, params);
	struct app_struct *app;
	struct access_histogram *hg;

	if (!m_page) {
		pr_err("Didn't find page %llu\n", pfn);
		return 0;
	}
	app_idx = m_page->apps_idx;
	app = &apps[app_idx];
	hg = &app->hg;
	
	spin_lock(&total_pages_lock[app_idx]);
	spin_lock(&m_page->lock);

	list_del(&m_page->t_list);

	hg_idx = m_page->hg_idx;

	page_list_del(m_page, &mtat_pages[m_page->hotness][app_idx][m_page->nid]);
	page_list_add(m_page, &f_pages[m_page->nid]);

	spin_lock(&hg->lock);

	hg->histogram[hg_idx]--;

	spin_unlock(&hg->lock);
	spin_unlock(&m_page->lock);
	spin_unlock(&total_pages_lock[app_idx]);

	return 0;
}

static void build_page_list(void)
{
	int i, j, k, nid, nb_pages = 0;
	struct hstate *h;
	struct page *page;

	init_apps();
	for (i = 0; i < NR_MEM_TYPES; i++) 
		init_page_list(&f_pages[i]);
	for (i = 0; i < MAX_APPS; i++) {
		for (j = 0; j < NR_MEM_TYPES; j++) {
			for (k = 0; k < NR_HOTNESS_TYPES; k++)
				init_page_list(&mtat_pages[k][i][j]);
		}
		INIT_LIST_HEAD(&total_pages[i]);
		spin_lock_init(&total_pages_lock[i]);
	}

	for_each_hstate(h) {
		for (nid = 0; nid < NR_MEM_TYPES; nid++) {
			if (nid != memory_nodes[0] && nid != memory_nodes[1])
				continue;

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

	total_dram_pages = get_num_pages(&f_pages[FASTMEM]);
	pr_info("Successfully created a list of %d pages\n", nb_pages);
}

static void reserve_page(struct hstate *h, int nid, pid_t pid, 
		struct mtat_page *m_page)
{
	struct app_struct *app;
	struct access_histogram *hg;
	int i, app_idx, pids_idx;
	bool need_add_dir = false;

	if (MTAT_MIGRATION_MODE != MTAT) {
		app_idx = 0;
		app = &apps[app_idx];
		spin_lock(&app->lock);
		if (app->pid == PID_NONE) {
			app->pid = 0;
			mtat_sysfs_apps_dir_add_dirs(mtat_sysfs->apps_dir, app_idx);
		}
		for (i = 0; i < MAX_APPS; i++) {
			if (app->_pids[i] == PID_NONE || app->_pids[i] == pid) {
				pids_idx = i;
				if (app->_pids[i] == PID_NONE) {
					pr_info("%dth new app is added - pid: %d\n", i, pid);
					app->_pids[i] = pid;
					mtat_sysfs_app_dir_add_dirs(mtat_sysfs->apps_dir, pids_idx);
				}
				break;
			}
		}
		spin_unlock(&app->lock);

		if (i == MAX_APPS) {
			pr_err("Too many apps!\n");
			return;
		}
		goto m_page_init;
	}

	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		spin_lock(&app->lock);
		if (app->pid == PID_NONE || app->pid == pid) {
			if (app->pid == PID_NONE) {
				need_add_dir = true;
				app->pid = pid;
			}
			spin_unlock(&app->lock);
			app_idx = i;
			if (need_add_dir)
				mtat_sysfs_apps_dir_add_dirs(mtat_sysfs->apps_dir, app_idx);
			break;
		}
		spin_unlock(&app->lock);
	}
	if (i == MAX_APPS) {
		pr_err("Too many apps!\n");
		return;
	}

m_page_init:
	hg = &app->hg;

	spin_lock(&total_pages_lock[app_idx]);
	spin_lock(&m_page->lock);

	m_page->hotness = COLD;
	m_page->apps_idx = app_idx;
	if (MTAT_MIGRATION_MODE != MTAT) 
		m_page->pids_idx = pids_idx;
	m_page->nid = nid;
	m_page->accesses = 0;
	m_page->hg_idx = 0;
	page_list_add(m_page, &mtat_pages[COLD][app_idx][nid]);

	list_add_tail(&m_page->t_list, &total_pages[app_idx]);

	spin_lock(&hg->lock);

	hg->histogram[0]++;

	spin_unlock(&hg->lock);

	list_move(&m_page->page->lru, &h->hugepage_activelist);
	set_page_count(m_page->page, 1);
	ClearHPageFreed(m_page->page);
	h->free_huge_pages--;
	h->free_huge_pages_node[nid]--;

	spin_unlock(&m_page->lock);
	spin_unlock(&total_pages_lock[app_idx]);
}

static struct page *__mtat_allocate_page(struct hstate *h, int nid, pid_t pid)
{
	struct page *page = NULL;
	struct mtat_page *m_page = NULL;
	int i;

	lockdep_assert_held(&hugetlb_lock);

	for (i = 0; i < NR_MEM_TYPES; i++) {
		if (i != memory_nodes[0] && i != memory_nodes[1])
			continue;
		spin_lock(&f_pages[i].lock);
		m_page = list_first_entry_or_null(&f_pages[i].list, struct mtat_page, list);
		if (m_page) {
			list_del(&m_page->list);
			f_pages[i].num_pages--;
		}
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
static void sync_mtat_page_after_migration(struct migration_target_control *mtc,
		struct mtat_page *m_page)
{
	int prev_idx, cur_idx;
	int app_idx;
	struct app_struct *app;
	struct access_histogram *hg;

	if (mtc->hotness == COLD)
		return;

	spin_lock(&m_page->lock);
	
	prev_idx = m_page->hg_idx;
	app_idx = m_page->apps_idx;
	app = &apps[app_idx];
	hg = &app->hg;
	spin_lock(&hg->lock);
	switch (mtc->hotness) {
	case HOT:
		m_page->accesses = hg_get_accesses(hg->hot_threshold);
		break;
	case WARM:
		m_page->accesses = hg_get_accesses(hg->warm_threshold);
		break;
	}
	spin_unlock(&hg->lock);

	cur_idx = hg_get_idx(m_page->accesses);
	m_page->hg_idx = cur_idx;

	update_page_list_with_mpage(m_page);

	spin_lock(&hg->lock);

	hg->histogram[prev_idx]--;
	hg->histogram[cur_idx]++;

	spin_unlock(&hg->lock);
	spin_unlock(&m_page->lock);

	}

static struct page *mtat_alloc_migration_target(struct page *old, unsigned long private)
{
	struct hstate *h = page_hstate(old);
	struct migration_target_control *mtc = (void*)private;
	struct mtat_page *m_page = NULL;
	struct page *page = NULL;

	spin_lock(&f_pages[mtc->nid].lock);
	m_page = list_first_entry_or_null(&f_pages[mtc->nid].list, struct mtat_page, list);
	if (m_page) {
		list_del(&m_page->list);
		f_pages[mtc->nid].num_pages--;
	}
	spin_unlock(&f_pages[mtc->nid].lock);

	if (m_page) {
		page = m_page->page;
		reserve_page(h, mtc->nid, mtc->pid, m_page);
		sync_mtat_page_after_migration(mtc, m_page);
	}

	return page;
}

static unsigned int migrate_page_list(struct list_head *page_list, int nid, int pid, 
									  struct app_struct *app, int hotness)
{
	unsigned int nr_migrated_pages = 0;
	struct page *page;
	struct page *page2;
	struct mtat_debug_info *debug = &app->debug;

	struct migration_target_control mtc = {
		.nid = nid,
		.pid = pid,
		.hotness = hotness
	};

	if (list_empty(page_list))
		return 0;

	if (migrate_pages(page_list, mtat_alloc_migration_target,
				NULL, (unsigned long)&mtc, MIGRATE_SYNC,
				MR_NUMA_MISPLACED, &nr_migrated_pages)) {
		//pr_err("migration partially failed.\n");
		list_for_each_entry_safe(page, page2, page_list, lru) {
			putback_active_hugepage(page);
		}
	}

	spin_lock(&debug->lock);
	debug->nr_migrated += nr_migrated_pages * 4 / 1024; // 4KB pages -> MB
	spin_unlock(&debug->lock);

	return nr_migrated_pages;
}

static unsigned int isolate_mtat_pages(struct page_list *from, 
		struct list_head *to, int target_nr)
{
	struct mtat_page *m_page = NULL;
	struct mtat_page *tmp = NULL;
	int nr = 0;

	if (target_nr == 0)
		return 0;

	list_for_each_entry_safe(m_page, tmp, &from->list, list) {
		if (nr >= target_nr)
			break;

		spin_lock(&m_page->lock);
		if (isolate_hugetlb(m_page->page, to)) {
			spin_unlock(&m_page->lock);
			continue;
		}
		spin_unlock(&m_page->lock);

		nr++;
	}

	return nr;
}

static void calculate_migration_target_size(int *target_promote,
		int *target_demote, int app_idx, int dram_size)
{
	int nr_fmem[NR_HOTNESS_TYPES], nr_smem[NR_HOTNESS_TYPES];
	int dram_leftover, nr_need_demote = 0, total_dram_size = 0;
	int i;
	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		nr_fmem[i] = get_num_pages(&mtat_pages[i][app_idx][FASTMEM]);
		nr_smem[i] = get_num_pages(&mtat_pages[i][app_idx][SLOWMEM]);
		target_promote[i] = 0;
		target_demote[i] = 0;

		total_dram_size += nr_fmem[i];
	}

	dram_leftover = dram_size;
	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		dram_leftover = max(0, dram_leftover - nr_fmem[i]);
		if (dram_leftover == 0)
			break;

		target_promote[i] = min(dram_leftover, nr_smem[i]);
		dram_leftover -= target_promote[i];
		total_dram_size += target_promote[i];
	}

	nr_need_demote = total_dram_size - dram_size;
	for (i = NR_HOTNESS_TYPES-1; i >= 0; i--) {
		if (nr_need_demote <= 0)
			break;
		target_demote[i] = min(nr_need_demote, nr_fmem[i]);
		nr_need_demote -= target_demote[i];
	}
}

static void mtat_migration(void)
{
	struct list_head promote_pages[MAX_APPS][NR_HOTNESS_TYPES];
	struct list_head demote_pages[MAX_APPS][NR_HOTNESS_TYPES];
	struct app_struct *app;
	int target_promote[MAX_APPS][NR_HOTNESS_TYPES], target_demote[MAX_APPS][NR_HOTNESS_TYPES]; 
	int i, j, app_num;
	uint64_t dram_size;

	for (i = 0; i < MAX_APPS; i++) {
		for (j = 0; j < NR_HOTNESS_TYPES; j++) {
			INIT_LIST_HEAD(&promote_pages[i][j]);
			INIT_LIST_HEAD(&demote_pages[i][j]);
			target_promote[i][j] = 0;
			target_demote[i][j] = 0;
		}
	}

	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE) {
			app_num = i;
			break;
		}
		spin_lock(&app->lock);
		dram_size = app->set_dram_size;
		spin_unlock(&app->lock);
		calculate_migration_target_size(target_promote[i], target_demote[i], i, dram_size);
	}

	/* Isolate pages for migration */
	for (i = 0; i < app_num; i++) {
		for (j = 0; j < NR_HOTNESS_TYPES; j++) {
			isolate_mtat_pages(&mtat_pages[j][i][SLOWMEM], &promote_pages[i][j], target_promote[i][j]);
			isolate_mtat_pages(&mtat_pages[j][i][FASTMEM], &demote_pages[i][j], target_demote[i][j]);
		}
	}

	/* Do Migration */
	for (i = 0; i < app_num; i++) {
		for (j = NR_HOTNESS_TYPES-1; j >= 0; j--) {
			migrate_page_list(&demote_pages[i][j], SLOWMEM, apps[i].pid, &apps[i], j);
		}
	}
	for (i = 0; i < app_num; i++) {
		for (j = 0; j < NR_HOTNESS_TYPES; j++) {
			migrate_page_list(&promote_pages[i][j], FASTMEM, apps[i].pid, &apps[i], j);	
		}
	}
}

static unsigned int memtis_isolate_mtat_pages(struct page_list *from, 
		struct list_head *to, int target_nr, bool demote)
{
	struct mtat_page *m_page = NULL;
	int nr = 0;
	int pids_idx, i;
	int added_pages[MAX_APPS] = {0, };
	uint64_t set_dram_size[MAX_APPS] = {0, };
	struct app_struct *app;

	if (target_nr == 0)
		return 0;

	app = &apps[0];
	spin_lock(&app->lock);
	for (i = 0; i < MAX_APPS; i++) {
		set_dram_size[i] = app->_set_dram_size[i];
	}
	spin_unlock(&app->lock);

	spin_lock(&from->lock);
	list_for_each_entry(m_page, &from->list, list) {
		if (nr >= target_nr)
			break;
		pids_idx = m_page->pids_idx;

		/*
		if (demote) {
			if ((app->_dram_pages[pids_idx] - added_pages[pids_idx] - 1) < set_dram_size[pids_idx])
				continue;
		} else {
			if ((app->_dram_pages[pids_idx] + added_pages[pids_idx] + 1) > set_dram_size[pids_idx])
				continue;
		}
		*/

		if (!demote) {
			if ((app->_dram_pages[pids_idx] + added_pages[pids_idx] + 1) > set_dram_size[pids_idx])
				continue;
		}

		if (isolate_hugetlb(m_page->page, &to[pids_idx]))
			continue;
		nr++;
		added_pages[pids_idx]++;
	}
	spin_unlock(&from->lock);

	return nr;
}

static void memtis_migration(void)
{
	struct list_head promote_pages[NR_HOTNESS_TYPES][MAX_APPS];
	struct list_head demote_pages[NR_HOTNESS_TYPES][MAX_APPS];
	struct app_struct *app;
	int target_promote[NR_HOTNESS_TYPES], target_demote[NR_HOTNESS_TYPES]; 
	int i, j;
	uint64_t dram_size;

	for (i = 0; i < MAX_APPS; i++) {
		for (j = 0; j < NR_HOTNESS_TYPES; j++) {
			INIT_LIST_HEAD(&promote_pages[j][i]);
			INIT_LIST_HEAD(&demote_pages[j][i]);
			target_promote[j] = 0;
			target_demote[j] = 0;
		}
	}

	app = &apps[0];

	if (app->pid == PID_NONE)
		return;

	spin_lock(&app->lock);
	dram_size = app->set_dram_size;
	spin_unlock(&app->lock);
	calculate_migration_target_size(target_promote, target_demote, 0, dram_size);

	/* Isolate pages for migration */
	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		memtis_isolate_mtat_pages(&mtat_pages[i][0][SLOWMEM], promote_pages[i], target_promote[i], false);
		memtis_isolate_mtat_pages(&mtat_pages[i][0][FASTMEM], demote_pages[i], target_demote[i], true);
	}

	/* Do Migration */
	for (i = 0; i < MAX_APPS; i++) {
		if (app->_pids[i] == PID_NONE)
			break;
		for (j = NR_HOTNESS_TYPES-1; j >= 0; j--) {
			migrate_page_list(&demote_pages[j][i], SLOWMEM, app->_pids[i], app, j);
		}
	}
	for (i = 0; i < MAX_APPS; i++) {
		if (app->_pids[i] == PID_NONE)
			break;
		for (j = 0; j < NR_HOTNESS_TYPES; j++) {
			migrate_page_list(&promote_pages[j][i], FASTMEM, app->_pids[i], app, j);	
		}
	}
}

//TODO Hemem, Memtis, MTAT 모드 구분하도록 하기.
static void do_migration(void)
{
	switch(MTAT_MIGRATION_MODE) {
	case MTAT:
		mtat_migration();
		break;
	case MEMTIS:
		memtis_migration();
		break;
	}
}

static void update_histogram(void)
{
	int i;
	uint64_t dram_size;
	struct app_struct *app;
	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE) {
			break;
		}
		spin_lock(&app->lock);
		dram_size = app->set_dram_size;
		spin_unlock(&app->lock);
		hg_update_hot_threshold(&app->hg, dram_size);
	}
}

void update_app_pages_info(void)
{
	struct app_struct *app;
	int i, j, k, tmp, dram_pages, total_pages;
	int _dram_pages[MAX_APPS]={0,};
	int _total_pages[MAX_APPS] = {0,};
	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE) {
			break;
		}

		dram_pages = 0;
		total_pages = 0;
		for (j = 0; j < NR_HOTNESS_TYPES; j++) {
			tmp = get_num_pages(&mtat_pages[j][i][FASTMEM]);
			dram_pages += tmp;
			total_pages += tmp + get_num_pages(&mtat_pages[j][i][SLOWMEM]);
			if (MTAT_MIGRATION_MODE != MTAT) {
				for (k = 0; k < MAX_APPS; k++) {
					if (app->_pids[k] == PID_NONE)
						break;
					tmp = get_num_pages_pid(&mtat_pages[j][i][FASTMEM], k);
					_dram_pages[k] += tmp;
					_total_pages[k] += tmp + get_num_pages_pid(&mtat_pages[j][i][SLOWMEM], k);
				}
			}
		}

		spin_lock(&app->lock);

		app->dram_pages = dram_pages;
		app->total_pages = total_pages;

		if (MTAT_MIGRATION_MODE != MTAT) {
			for (k = 0; k < MAX_APPS; k++) {
				if (app->_pids[k] == PID_NONE)
					break;
				app->_dram_pages[k] = _dram_pages[k];
				app->_total_pages[k] = _total_pages[k];
			}
		}

		spin_unlock(&app->lock);

	}
}

static int kmigrated_main(void *data)
{
	pr_info("kmigrated start\n");

	mtat_set_cpu_affinity(KMIGRATED_CPU);

	while (!kthread_should_stop()) {
		update_histogram();

		if (migrate_on) {
			do_migration();
		}

		update_app_pages_info();
		
		msleep(mtat_migration_period);
		if (need_resched())
			schedule();
	}
	pr_info("kmigrated exit\n");
	return 0;
}

/*
 * Cooling daemon
 */
static void update_fixed_hg(void)
{
	struct app_struct *app;
	struct access_histogram *hg;
	uint64_t tmp_hg[16];
	int i, j;
	for (i = 0; i < MAX_APPS; i++) {
		app = &apps[i];
		if (app->pid == PID_NONE) {
			break;
		}
		hg = &app->hg;
		spin_lock(&hg->lock);
		for (j = 0; j < 16; j++)
			tmp_hg[j] = hg->histogram[j];
		spin_unlock(&hg->lock);

		spin_lock(&app->lock);
		for (j = 0; j < 16; j++)
			app->fixed_hg[j] = tmp_hg[j];
		spin_unlock(&app->lock);
	}
}

static int kcoolingd_main(void *data)
{
	pr_info("kcoolingd start\n");

	mtat_set_cpu_affinity(KMIGRATED_CPU);

	while (!kthread_should_stop()) {
		update_fixed_hg();
		
		periodic_cooling();
		msleep(cooling_period);
		if (need_resched())
			schedule();
	}
	pr_info("kcoolingd exit\n");
	return 0;
}

/*
 * SYSFS functions
 */
static ssize_t migrate_on_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	return sysfs_emit(buf, "%lu\n", migrate_on);
}

static ssize_t migrate_on_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long input;
	int err;

	err = kstrtoul(buf, 0, &input);
	if (err)
		return err;

	migrate_on = input;
	return count;
}

static ssize_t pebs_on_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	return sysfs_emit(buf, "%lu\n", pebs_on);
}

static ssize_t pebs_on_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long input;
	int err;

	err = kstrtoul(buf, 0, &input);
	if (err)
		return err;

	pebs_on = input;
	return count;
}

static ssize_t mtat_debug_on_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	return sysfs_emit(buf, "%lu\n", mtat_debug_on);
}

static ssize_t mtat_debug_on_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long input;
	int err;

	err = kstrtoul(buf, 0, &input);
	if (err)
		return err;

	mtat_debug_on = input;
	return count;
}

static ssize_t total_dram_pages_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	return sysfs_emit(buf, "%lu\n", total_dram_pages);
}

static struct kobj_attribute migrate_on_attr = __ATTR_RW_MODE(migrate_on, 0600);
static struct kobj_attribute pebs_on_attr = __ATTR_RW_MODE(pebs_on, 0600);
static struct kobj_attribute mtat_debug_on_attr = __ATTR_RW_MODE(mtat_debug_on, 0600);
static struct kobj_attribute total_dram_pages_attr = __ATTR_RO_MODE(total_dram_pages, 0400);

/*
 * memtis_dir
 */
static ssize_t _set_dram_size_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_memtis_dir *memtis_dir =container_of(kobj, struct mtat_sysfs_memtis_dir, kobj);
	struct app_struct *app = &apps[0];
	int pids_idx = memtis_dir->pids_idx;
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->_set_dram_size[pids_idx]);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t _set_dram_size_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct mtat_sysfs_memtis_dir *memtis_dir =container_of(kobj, struct mtat_sysfs_memtis_dir, kobj);
	struct app_struct *app = &apps[0];
	int pids_idx = memtis_dir->pids_idx;
	unsigned long input  = 0;
	int err;

	err = kstrtoul(buf, 0, &input);
	if (err)
		return err;

	spin_lock(&app->lock);
	app->_set_dram_size[pids_idx] = input;
	spin_unlock(&app->lock);

	return count;
}

static ssize_t _dram_pages_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_memtis_dir *memtis_dir =container_of(kobj, struct mtat_sysfs_memtis_dir, kobj);
	struct app_struct *app = &apps[0];
	int pids_idx = memtis_dir->pids_idx;
	int len = 0;


	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->_dram_pages[pids_idx]);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t _total_pages_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_memtis_dir *memtis_dir =container_of(kobj, struct mtat_sysfs_memtis_dir, kobj);
	struct app_struct *app = &apps[0];
	int pids_idx = memtis_dir->pids_idx;
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->_total_pages[pids_idx]);
	spin_unlock(&app->lock);

	return len;
}

static struct kobj_attribute _set_dram_size_attr = __ATTR_RW_MODE(_set_dram_size, 0600);
static struct kobj_attribute _dram_pages_attr = __ATTR_RO_MODE(_dram_pages, 0400);
static struct kobj_attribute _total_pages_attr = __ATTR_RO_MODE(_total_pages, 0400);

static struct attribute *mtat_sysfs_memtis_dir_attrs[] = {
	&_set_dram_size_attr.attr,
	&_dram_pages_attr.attr,
	&_total_pages_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_memtis_dir);

static struct kobj_type mtat_sysfs_memtis_dir_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_memtis_dir_groups,
};

/*
 * app_dir
 */
static int mtat_sysfs_app_dir_add_dirs(struct mtat_sysfs_apps_dir *apps_dir, int pids_idx)
{
	struct mtat_sysfs_app_dir *app_dir = &apps_dir->app_dirs[0];
	struct mtat_sysfs_memtis_dir *memtis_dir = &app_dir->memtis_dirs[pids_idx];
	struct app_struct *app = &apps[0];
	int pid = app->_pids[pids_idx];
	int err;

	memtis_dir->pids_idx = pids_idx;

	err = kobject_init_and_add(&memtis_dir->kobj,
			&mtat_sysfs_memtis_dir_ktype, &app_dir->kobj,
			"%d", pid);
	if (err)
		kobject_put(&memtis_dir->kobj);

	return err;
}

static ssize_t set_dram_size_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	unsigned long input;
	int err;

	err = kstrtoul(buf, 0, &input);
	if (err)
		return err;

	spin_lock(&app->lock);
	app->set_dram_size = input;
	spin_unlock(&app->lock);

	return count;
}

static ssize_t set_dram_size_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->set_dram_size);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t nr_total_sampled_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->nr_total_sampled);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t nr_fmem_read_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->nr_fmem_read);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t nr_smem_read_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->nr_smem_read);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t dram_pages_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->dram_pages);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t total_pages_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	int len = 0;

	spin_lock(&app->lock);
	len = snprintf(buf, PAGE_SIZE, "%llu\n", app->total_pages);
	spin_unlock(&app->lock);

	return len;
}

static ssize_t histogram_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	struct mtat_sysfs_app_dir *app_dir =container_of(kobj, struct mtat_sysfs_app_dir, kobj);
	struct app_struct *app = &apps[app_dir->app_idx];
	int i, len = 0, ret;
	size_t buf_size = PAGE_SIZE;

	spin_lock(&app->lock);
	for (i = 0; i < 16; i++) {
		ret = snprintf(buf + len, buf_size - len, "%llu ", app->fixed_hg[i]);

		if (ret >= buf_size - len) 
			break;

		len += ret;
	}
	spin_unlock(&app->lock);

	return len;
}

static struct kobj_attribute set_dram_size_attr = __ATTR_RW_MODE(set_dram_size, 0600);
static struct kobj_attribute nr_total_sampled_attr = __ATTR_RO_MODE(nr_total_sampled, 0400);
static struct kobj_attribute nr_fmem_read_attr = __ATTR_RO_MODE(nr_fmem_read, 0400);
static struct kobj_attribute nr_smem_read_attr = __ATTR_RO_MODE(nr_smem_read, 0400);
static struct kobj_attribute dram_pages_attr = __ATTR_RO_MODE(dram_pages, 0400);
static struct kobj_attribute total_pages_attr = __ATTR_RO_MODE(total_pages, 0400);
static struct kobj_attribute histogram_attr = __ATTR_RO_MODE(histogram, 0400);

static struct attribute *mtat_sysfs_app_dir_attrs[] = {
	&set_dram_size_attr.attr,
	&nr_total_sampled_attr.attr,
	&nr_fmem_read_attr.attr,
	&nr_smem_read_attr.attr,
	&dram_pages_attr.attr,
	&total_pages_attr.attr,
	&histogram_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_app_dir);

static struct kobj_type mtat_sysfs_app_dir_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_app_dir_groups,
};

/*
 * apps_dir
 */
static struct mtat_sysfs_apps_dir *mtat_sysfs_apps_dir_alloc(void)
{
	struct mtat_sysfs_apps_dir *apps_dir;
	struct mtat_sysfs_app_dir *app_dir;
	struct mtat_sysfs_memtis_dir *memtis_dir;
	int i, j;
	apps_dir = kzalloc(sizeof(struct mtat_sysfs_apps_dir), GFP_KERNEL);
	if (!apps_dir)
		goto out;
	
	for (i = 0; i < MAX_APPS; i++) {
		app_dir = &apps_dir->app_dirs[i];
		app_dir->app_idx = PID_NONE;
		for (j = 0; j < MAX_APPS; j++) {
			memtis_dir = &app_dir->memtis_dirs[j];
			memtis_dir->pids_idx = PID_NONE;
		}
	}

out:
	return apps_dir;
}

static int mtat_sysfs_apps_dir_add_dirs(struct mtat_sysfs_apps_dir *apps_dir, int app_idx)
{
	struct mtat_sysfs_app_dir *app_dir = &apps_dir->app_dirs[app_idx];
	struct app_struct *app = &apps[app_idx];
	int err;

	app_dir->app_idx = app_idx;

	err = kobject_init_and_add(&app_dir->kobj,
			&mtat_sysfs_app_dir_ktype, &apps_dir->kobj,
			"%d", app->pid);
	if (err)
		kobject_put(&app_dir->kobj);

	return err;
}

static void mtat_sysfs_apps_dir_release(struct kobject *kobj)
{
	kfree(container_of(kobj, struct mtat_sysfs_apps_dir, kobj));
}

static struct attribute *mtat_sysfs_apps_dir_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_apps_dir);

static struct kobj_type mtat_sysfs_apps_dir_ktype = {
	.release = mtat_sysfs_apps_dir_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_apps_dir_groups,
};

/* 
 * ui_dir
 */
static struct mtat_sysfs_ui_dir *mtat_sysfs_ui_dir_alloc(void)
{
	return kzalloc(sizeof(struct mtat_sysfs_ui_dir), GFP_KERNEL);
}

static int mtat_sysfs_ui_dir_add_dirs(struct mtat_sysfs_ui_dir *ui_dir)
{
	struct mtat_sysfs_apps_dir *apps_dir;
	int err;

	apps_dir = mtat_sysfs_apps_dir_alloc();
	if (!apps_dir)
		return -ENOMEM;

	err = kobject_init_and_add(&apps_dir->kobj,
			&mtat_sysfs_apps_dir_ktype, &ui_dir->kobj,
			"apps");
	if (err) {
		kobject_put(&apps_dir->kobj);
		return err;
	}
	ui_dir->apps_dir = apps_dir;
	return err;
}

static void mtat_sysfs_ui_dir_release(struct kobject *kobj)
{
	kfree(mtat_sysfs);
}

static struct attribute *mtat_sysfs_ui_dir_attrs[] = {
	&migrate_on_attr.attr,
	&pebs_on_attr.attr,
	&mtat_debug_on_attr.attr,
	&total_dram_pages_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mtat_sysfs_ui_dir);

static struct kobj_type mtat_sysfs_ui_dir_ktype = {
	.release = mtat_sysfs_ui_dir_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = mtat_sysfs_ui_dir_groups,
};

static int mtat_sysfs_init(void)
{
	int err;

	mtat_sysfs = mtat_sysfs_ui_dir_alloc();
	if (!mtat_sysfs) {
		return -ENOMEM;
	}
	err = kobject_init_and_add(&mtat_sysfs->kobj, &mtat_sysfs_ui_dir_ktype,
			mm_kobj, "mtat");
	if (err)
		goto out;
	err = mtat_sysfs_ui_dir_add_dirs(mtat_sysfs);
	if (err)
		goto out;
	return 0;

out:
	kobject_put(&mtat_sysfs->kobj);
	return err;
}

static void mtat_sysfs_exit(void)
{
	struct mtat_sysfs_apps_dir *apps_dir;
	struct mtat_sysfs_app_dir *app_dir;
	struct mtat_sysfs_memtis_dir *memtis_dir;
	int i,j;
	if (mtat_sysfs) {
		apps_dir = mtat_sysfs->apps_dir;
		for (i = 0; i < MAX_APPS; i++) {
			app_dir = &apps_dir->app_dirs[i];
			if (app_dir->app_idx == PID_NONE)
				continue;
			for (j = 0; j < MAX_APPS; j++) {
				memtis_dir = &app_dir->memtis_dirs[j];
				if (memtis_dir->pids_idx != PID_NONE)
					kobject_put(&memtis_dir->kobj);
			}
			kobject_put(&app_dir->kobj);
		}
		kobject_put(&apps_dir->kobj);
		kobject_put(&mtat_sysfs->kobj);
	}
}

/*
 * MTAT initialization
 */
int init_module(void)
{
	if (mtat_sysfs_init()) {
		pr_err("Failed to init mtat sysfs\n");
		return -1;
	}

	FASTMEM = memory_nodes[0];
	SLOWMEM = memory_nodes[1];

	if (init_hashtable())
		return -1;

	build_page_list();

	set_dequeue_hook(mtat_allocate_page);
	set_enqueue_hook(mtat_free_page);

	// pebs init
	pebs_start();

	kdebugd = kthread_run(kdebugd_main, NULL, "kdebugd");
	if (IS_ERR(kdebugd)) {
		pr_err("Failed to create kdebugd\n");
	}

	kmigrated = kthread_run(kmigrated_main, NULL, "kmigrated");
	if (IS_ERR(kmigrated)) {
		pr_err("Failed to create kmigrated\n");
	}

	kcoolingd = kthread_run(kcoolingd_main, NULL, "kcoolingd");
	if (IS_ERR(kcoolingd)) {
		pr_err("Failed to create kcoolingd\n");
	}

	pr_info("Successfully insert MTAT module\n");
	return 0;
}

/*
 * MTAT exit
 */
void cleanup_module(void)
{
	if (kcoolingd)
		kthread_stop(kcoolingd);
	if (kmigrated)
		kthread_stop(kmigrated);
	if (kdebugd)
		kthread_stop(kdebugd);

	// pebs stop  
	pebs_stop();

	set_dequeue_hook(NULL);
	set_enqueue_hook(NULL);

	destroy_hashtable();
	
	mtat_sysfs_exit();
	pr_info("Remove MTAT module\n");
}

MODULE_AUTHOR("Minho Kim <mhkim@dgist.ac.kr>");
MODULE_DESCRIPTION("Multi-Tenant-Aware Tiered Memory Management");
MODULE_LICENSE("GPL v2");
