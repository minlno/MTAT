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

/*
 * Module parameters
 */
static int migrate_on = 0;
module_param(migrate_on, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
static int pebs_on = 1;
module_param(pebs_on, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

static int min_hot_threshold = 1;
module_param(min_hot_threshold, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
static int set_lc_dram_size = 0; // 2MB page 개수 -1이 아닌경우 무조건 이값으로 warm size를 유지
module_param(set_lc_dram_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

static int cooling_period = 1000; // ms
module_param(cooling_period, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
static int zero_cooling_on = 0;
module_param(zero_cooling_on, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

/*
static int min_warm_size = 1000; // 2MB page 개수
module_param(min_warm_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
static int warm_percent = 50; // %
module_param(warm_percent, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
static int static_warm_size = -1; // 2MB page 개수 -1이 아닌경우 무조건 이값으로 warm size를 유지
module_param(static_warm_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
*/

static int mtat_debug_on = 1;
module_param(mtat_debug_on, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

static int mtat_migration_rate = 5000; // 2MB page 개수
module_param(mtat_migration_rate, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
static int mtat_migration_period = 1; // ms
module_param(mtat_migration_period, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

static int lc_dram_pages = -1; // 2MB pages
module_param(lc_dram_pages, int, S_IRUSR | S_IRGRP | S_IROTH);
static int lc_total_pages = -1; // 2MB pages
module_param(lc_total_pages, int, S_IRUSR | S_IRGRP | S_IROTH);
static int total_dram_pages = -1; // 2MB pages
module_param(total_dram_pages, int, S_IRUSR | S_IRGRP | S_IROTH);


/*
 * For Debug
 */
static uint64_t lc_hg[16]; // it is for training LC RL model
static uint64_t lc_nr_sampled; // it is for training LC RL model
static uint64_t lc_nr_read; // it is for training LC RL model
static uint64_t lc_nr_dram_read; // it is for training LC RL model
static uint64_t lc_nr_smem_read; // it is for training LC RL model
static uint64_t debug_nr_sampled[4];
static uint64_t debug_nr_skip;
static uint64_t debug_nr_throttled;
static uint64_t debug_nr_found;
static uint64_t debug_nr_not_found;
static uint64_t debug_nr_losted;
static uint64_t debug_nr_cooled;
static uint64_t debug_nr_migrated;
static spinlock_t debug_lock;

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
static struct access_histogram hg[MAX_PIDS];
static struct list_head total_pages[MAX_PIDS];
static spinlock_t total_pages_lock[MAX_PIDS];

static void init_hg(void)
{
	int i;
	for (i = 0; i < MAX_PIDS; i++) {
		spin_lock_init(&hg[i].lock);
		hg[i].hot_threshold = min_hot_threshold;
		hg[i].warm_threshold = min_hot_threshold - 1;

		hg[i].nr_sampled = 0;
	}
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

// hg lock 잡지 않고 호출해야함.
static void hg_update_hot_threshold(uint64_t hg_idx, uint64_t dram_size)
{
	uint64_t tmp = 0;
	int i;

	spin_lock(&hg[hg_idx].lock);
	for (i = 15; i >= 0; i--) {
		tmp += hg[hg_idx].hg[i];
		if (tmp > dram_size) {
			hg[hg_idx].hot_threshold = i+1;
			hg[hg_idx].warm_threshold = i;
			spin_unlock(&hg[hg_idx].lock);
			return;
		}
	}
	hg[hg_idx].hot_threshold = min_hot_threshold;
	hg[hg_idx].warm_threshold = min_hot_threshold - 1;
	spin_unlock(&hg[hg_idx].lock);
}

/*
 * Histogram Sysfs
 */
static ssize_t lc_hg_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int i, len = 0, ret;
	size_t buf_size = PAGE_SIZE;

	spin_lock(&debug_lock);
	for (i = 0; i < 16; i++) {
		ret = snprintf(buf + len, buf_size - len, "%llu ", lc_hg[i]);

		if (ret >= buf_size - len) 
			break;

		len += ret;
	}
	spin_unlock(&debug_lock);

	return len;
}
static struct kobj_attribute lc_hg_attr = __ATTR_RO(lc_hg);

static ssize_t lc_nr_sampled_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int i, len = 0, ret;

	spin_lock(&debug_lock);

	len = snprintf(buf, PAGE_SIZE, "%llu", lc_nr_sampled);

	spin_unlock(&debug_lock);

	return len;
}
static struct kobj_attribute lc_nr_sampled_attr = __ATTR_RO(lc_nr_sampled);

static ssize_t lc_nr_read_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int i, len = 0, ret;

	spin_lock(&debug_lock);

	len = snprintf(buf, PAGE_SIZE, "%llu", lc_nr_read);

	spin_unlock(&debug_lock);

	return len;
}
static struct kobj_attribute lc_nr_read_attr = __ATTR_RO(lc_nr_read);

static ssize_t lc_nr_dram_read_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int i, len = 0, ret;

	spin_lock(&debug_lock);

	len = snprintf(buf, PAGE_SIZE, "%llu", lc_nr_dram_read);

	spin_unlock(&debug_lock);

	return len;
}
static struct kobj_attribute lc_nr_dram_read_attr = __ATTR_RO(lc_nr_dram_read);

static ssize_t lc_nr_smem_read_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int i, len = 0, ret;

	spin_lock(&debug_lock);

	len = snprintf(buf, PAGE_SIZE, "%llu", lc_nr_smem_read);

	spin_unlock(&debug_lock);

	return len;
}
static struct kobj_attribute lc_nr_smem_read_attr = __ATTR_RO(lc_nr_smem_read);

/*
 * Page list related variables and functions
 *
 * lock 규칙:
 * - list_del, list_add 모두 mtat_page->lock,  page_list->lock 잡은 후 수행.
 *
 * lock 순서:
 * total_pages_lock
 *  mtat_page->lock
 *   hg->lock, mtat_pages->lock, lock
 */
static int pids[MAX_PIDS];
static spinlock_t lock;

static struct page_list f_pages[NR_MEM_TYPES]; // free_pages
static struct page_list mtat_pages[NR_HOTNESS_TYPES][MAX_PIDS][NR_MEM_TYPES];

struct mtat_page *alloc_and_init_mtat_page(struct page *page)
{
	struct mtat_page *m_page = kmalloc(sizeof(*m_page), GFP_KERNEL);

	if (!m_page)
		return NULL;

	m_page->page = page;
	m_page->pfn = page_to_pfn(page) << PAGE_SHIFT >> HPAGE_SHIFT;
	m_page->accesses = 0;
	m_page->hotness = COLD;
	m_page->pids_idx = PID_NONE;
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

void page_list_del(struct mtat_page *m_page, struct page_list *pl)
{
	spin_lock(&pl->lock);
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
	spin_lock_init(&pl->lock);
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
 * kdebugd thread for debugging *
 **********************************
 */
static struct task_struct *kdebugd;

static void print_debug_stats(void)
{
	int i, j;
	uint64_t tmp_nr_sampled[4];
	uint64_t tmp_nr_cooled, tmp_nr_migrated;
	uint64_t tmp_nr_throttled, tmp_nr_losted;
	uint64_t tmp_nr_found, tmp_nr_not_found;
	uint64_t tmp_nr_skip;

	for (i = 0; i < MAX_PIDS; i++) {
		if (pids[i] == PID_NONE)
			continue;
		pr_info("=======================================\n");
		pr_info("pid: %d\n", pids[i]);
		for (j = 0; j < NR_MEM_TYPES; j++) {
			if (j != memory_nodes[0] && j != memory_nodes[1])
				continue;
			pr_info("--numa node: %d, free_pages: %d\n", j, get_num_pages(&f_pages[j]));
			pr_info("----hot_pages: %d\n", get_num_pages(&mtat_pages[HOT][i][j]));
			pr_info("----warm_pages: %d\n", get_num_pages(&mtat_pages[WARM][i][j]));
			pr_info("----cold_pages: %d\n", get_num_pages(&mtat_pages[COLD][i][j]));
		}
		// histogram
		pr_info("nr_sampled: %llu\n", hg[i].nr_sampled);
		//for (j = 0; j < 16; j++)
			//pr_info("%d: %llu", j, hg[i].hg[j]);
	}

	spin_lock(&debug_lock);

	for (i = 0; i < 4; i++)
		tmp_nr_sampled[i] = debug_nr_sampled[i];
	tmp_nr_found = debug_nr_found;
	tmp_nr_not_found = debug_nr_not_found;
	tmp_nr_cooled = debug_nr_cooled;
	tmp_nr_migrated = debug_nr_migrated;
	tmp_nr_throttled = debug_nr_throttled;
	tmp_nr_losted = debug_nr_losted;
	tmp_nr_skip = debug_nr_skip;

	memset(debug_nr_sampled, 0, sizeof(debug_nr_sampled));
	debug_nr_found = 0;
	debug_nr_not_found = 0;
	debug_nr_cooled = 0;
	debug_nr_migrated = 0;
	debug_nr_throttled = 0;
	debug_nr_losted = 0;
	debug_nr_skip = 0;

	lc_nr_sampled = tmp_nr_sampled[0] + tmp_nr_sampled[1] 
					+ tmp_nr_sampled[2] + tmp_nr_sampled[3];
	lc_nr_read = tmp_nr_sampled[0] + tmp_nr_sampled[1] + tmp_nr_sampled[2];
	lc_nr_dram_read = tmp_nr_sampled[0];
	lc_nr_smem_read = tmp_nr_sampled[1] + tmp_nr_sampled[2];

	spin_unlock(&debug_lock);

	pr_info("---------------------------------------\n");
	pr_info("nr_sampled: %llu\n", tmp_nr_sampled[0] + tmp_nr_sampled[1] 
								+ tmp_nr_sampled[2] + tmp_nr_sampled[3]);
	pr_info("----DRAM_READ: %llu\n", tmp_nr_sampled[0]);
#ifdef CXL_MODE
	pr_info("----CXL_READ: %llu\n", tmp_nr_sampled[2]);
#else
	pr_info("----PMEM_READ: %llu\n", tmp_nr_sampled[1]);
#endif
	pr_info("----STORE_ALL: %llu\n", tmp_nr_sampled[3]);
	pr_info("nr_found: %llu\n", tmp_nr_found);
	pr_info("nr_not_found: %llu\n", tmp_nr_not_found);
	pr_info("nr_found + nr_not_found: %llu\n", tmp_nr_found + tmp_nr_not_found);
	pr_info("nr_skip: %llu\n", tmp_nr_skip);
	pr_info("nr_throttled: %llu\n", tmp_nr_throttled);
	pr_info("nr_losted: %llu\n", tmp_nr_losted);
	pr_info("nr_cooled: %llu\n", tmp_nr_cooled);
	pr_info("nr_migrated: %llu MB\n", tmp_nr_migrated);
	pr_info("=======================================\n");

}

static int kdebugd_main(void *data)
{
	pr_info("kdebugd start\n");

	mtat_set_cpu_affinity(KDEBUGD_CPU);

	while (!kthread_should_stop()) {
		if (mtat_debug_on)
			print_debug_stats();
		ssleep(1);
	}

	pr_info("kdebugd exit\n");

	return 0;
}

/*
 ****************************************
 * PEBS related variables and functions *
 ****************************************
 */
static struct perf_event ***events;
static int **events_fd;

#ifdef CXL_MODE
static size_t configs[] = { DRAM_READ, CXL_READ, STORE_ALL };
#else
static size_t configs[] = { DRAM_READ, PMEM_READ, STORE_ALL };
#endif

static size_t cpus[] = {16,17,18,19,20,21,22,23,
					   48,49,50,51,52,53,54,55,56,57,58,59,
					   64,65,66,67,68,69,70,71};
//static size_t cpus[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,
//					   48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71};
//static size_t cpus[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23};
//static size_t cpus[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,
//						25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48};
static struct task_struct *kpebsd;

// m_page->lock을 잡고 호출해야함.
// hg->lock도 필요
static bool is_hot_page(struct mtat_page *m_page)
{
	uint64_t hot_access;

	hot_access = hg_get_accesses(hg[m_page->pids_idx].hot_threshold);

	if (m_page->accesses >= hot_access)
		return true;
	else 
		return false;
}

// m_page->lock 필요
// hg->lock도 필요
// hot도 true로 뱉음
static bool is_warm_page(struct mtat_page *m_page)
{
	uint64_t warm_access;
	warm_access = hg_get_accesses(hg[m_page->pids_idx].warm_threshold);

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
	int pids_idx = m_page->pids_idx;
	int nid = m_page->nid;
	

	spin_lock(&hg[pids_idx].lock);
	if (is_hot_page(m_page))
		cur_hotness = HOT;
	else if (is_warm_page(m_page))
		cur_hotness = WARM;
	else
		cur_hotness = COLD;
	spin_unlock(&hg[pids_idx].lock);

	if (prev_hotness == cur_hotness)
		return;

	m_page->hotness = cur_hotness;
	page_list_del(m_page, &mtat_pages[prev_hotness][pids_idx][nid]);
	page_list_add(m_page, &mtat_pages[cur_hotness][pids_idx][nid]);
}

static void partial_cooling_pid(int pid_idx)
{
	struct mtat_page *m_page;
	int nr_cooled = 0;
	int cur_access, prev_idx, cur_idx;

	spin_lock(&total_pages_lock[pid_idx]);
	list_for_each_entry(m_page, &total_pages[pid_idx], t_list) {
		spin_lock(&m_page->lock);

		// 접근횟수 cooling
		if (zero_cooling_on)
			m_page->accesses = 0;
		else
			m_page->accesses >>= 1;

		// 쿨링 후 필요하면 cold list로 보내기
		update_page_list_with_mpage(m_page);

		// 히스토그램 인덱스 계산
		prev_idx = m_page->hg_idx;
		cur_access = m_page->accesses;
		cur_idx = hg_get_idx(cur_access);
		m_page->hg_idx = cur_idx;



		// 쿨링 후 히스토그램 카운터 관리
		spin_lock(&hg[pid_idx].lock);

		hg[pid_idx].hg[prev_idx]--;
		hg[pid_idx].hg[cur_idx]++;
		if (cur_idx == 0 && prev_idx != 0)
			hg[pid_idx].nr_sampled--;

		spin_unlock(&hg[pid_idx].lock);
		spin_unlock(&m_page->lock);

		nr_cooled++;
	}
	spin_unlock(&total_pages_lock[pid_idx]);

	spin_lock(&debug_lock);
	debug_nr_cooled += nr_cooled;
	spin_unlock(&debug_lock);
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

static void pebs_sample(uint64_t pfn) 
{
	int nid, pid_idx;
	struct mtat_page *m_page = NULL;
	uint64_t cur_access, prev_idx, cur_idx;

	m_page = rhashtable_lookup_fast(hashtable, &pfn, params);
	if (!m_page) {
		//pr_info("pfn: %llu\n", pfn);
		spin_lock(&debug_lock);
		debug_nr_not_found++;
		spin_unlock(&debug_lock);
		return;
	}
	spin_lock(&debug_lock);
	debug_nr_found++;
	spin_unlock(&debug_lock);
	
	pid_idx = m_page->pids_idx;
	nid = m_page->nid;

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
	spin_lock(&hg[pid_idx].lock);

	hg[pid_idx].hg[prev_idx]--;
	hg[pid_idx].hg[cur_idx]++;
	if (prev_idx == 0 && cur_idx != 0)
		hg[pid_idx].nr_sampled++;

	spin_unlock(&hg[pid_idx].lock);
	spin_unlock(&m_page->lock);
}

static void pebs_restart(void);
static int kpebsd_main(void *data)
{
	struct perf_buffer *pe_rb;
	struct perf_event_mmap_page *p;
	struct perf_event_header *ph;
	struct perf_sample *ps;
	//char *pbuf;
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
					spin_lock(&debug_lock);
					debug_nr_skip++;
					spin_unlock(&debug_lock);
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

					spin_lock(&debug_lock);
					if (configs[config] == DRAM_READ)
						debug_nr_sampled[0]++;
					else if (configs[config] == PMEM_READ)
						debug_nr_sampled[1]++;
					else if (configs[config] == CXL_READ)
						debug_nr_sampled[2]++;
					else
						debug_nr_sampled[3]++;
					spin_unlock(&debug_lock);

					if (cpu != ps->cpu) {
						//pr_info("current v.s. sample: %lu, %u\n", cpu, ps->cpu);
						break;
					}

					pfn = perf_virt_to_phys(ps->addr, ps->pid) >> HPAGE_SHIFT;
					pebs_sample(pfn);
					break;
				case PERF_RECORD_THROTTLE:
				case PERF_RECORD_UNTHROTTLE:
					spin_lock(&debug_lock);
					debug_nr_throttled++;
					spin_unlock(&debug_lock);
					break;
				case PERF_RECORD_LOST_SAMPLES:
					spin_lock(&debug_lock);
					debug_nr_losted++;
					spin_unlock(&debug_lock);
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
	struct file *file;

	/* perf_event_stop 사용하는 방법 -> warning 메세지가 뜨는 문제 있음
	 * pebs sample 수가 줄어드는 지는 확인 중
	 */
	/*
	for (config = 0; config < ARRAY_SIZE(configs); config++) {
		for (cpu = 0; cpu < ARRAY_SIZE(cpus); cpu++) {
			perf_event_stop(events[cpu][config], 1);
		}
	}
	msleep(cooling_period);
	*/

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
			//file = fget(events_fd[cpu][config]);
			//fput(file);
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
	struct mtat_page *m_page = rhashtable_lookup_fast(hashtable, &pfn, params);
	int hg_idx;

	if (!m_page) {
		pr_err("Didn't find page %llu\n", pfn);
		return 0;
	}
	
	spin_lock(&total_pages_lock[m_page->pids_idx]);
	spin_lock(&m_page->lock);

	list_del(&m_page->t_list);

	hg_idx = m_page->hg_idx;

	page_list_del(m_page, &mtat_pages[m_page->hotness][m_page->pids_idx][m_page->nid]);
	page_list_add(m_page, &f_pages[m_page->nid]);

	spin_lock(&hg[m_page->pids_idx].lock);

	hg[m_page->pids_idx].hg[hg_idx]--;
	if (hg_idx != 0)
		hg[m_page->pids_idx].nr_sampled--;

	spin_unlock(&hg[m_page->pids_idx].lock);
	spin_unlock(&m_page->lock);
	spin_unlock(&total_pages_lock[m_page->pids_idx]);

	return 0;
}

static void build_page_list(void)
{
	int i, j, k, nid, nb_pages = 0;
	struct hstate *h;
	struct page *page;

	spin_lock_init(&lock);
	spin_lock_init(&debug_lock);
	for (i = 0; i < NR_MEM_TYPES; i++) 
		init_page_list(&f_pages[i]);
	for (i = 0; i < MAX_PIDS; i++) {
		pids[i] = PID_NONE;
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
	int i;

	/*
	if (MTAT_MIGRATION_MODE == HEMEM) {
		i = 0;
		pids[0] = 0;
		goto m_page_init;
	}
	*/

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

//m_page_init:
	spin_lock(&total_pages_lock[i]);
	spin_lock(&m_page->lock);

	m_page->hotness = COLD;
	m_page->pids_idx = i;
	m_page->nid = nid;
	m_page->accesses = 0;
	m_page->hg_idx = 0;
	page_list_del(m_page, &f_pages[nid]);
	page_list_add(m_page, &mtat_pages[COLD][i][nid]);

	list_add_tail(&m_page->t_list, &total_pages[i]);


	spin_lock(&hg[m_page->pids_idx].lock);

	hg[m_page->pids_idx].hg[0]++;

	spin_unlock(&hg[m_page->pids_idx].lock);
	spin_unlock(&m_page->lock);
	spin_unlock(&total_pages_lock[i]);


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
		if (i != memory_nodes[0] && i != memory_nodes[1])
			continue;
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

static void sync_mtat_page_after_migration(struct migration_target_control *mtc,
		struct mtat_page *m_page)
{
	int prev_idx, cur_idx;
	if (mtc->hotness == COLD)
		return;

	spin_lock(&m_page->lock);
	
	prev_idx = m_page->hg_idx;

	spin_lock(&hg[m_page->pids_idx].lock);
	switch (mtc->hotness) {
	case HOT:
		m_page->accesses = hg_get_accesses(hg[m_page->pids_idx].hot_threshold);
		break;
	case WARM:
		m_page->accesses = hg_get_accesses(hg[m_page->pids_idx].warm_threshold);
		break;
	}
	spin_unlock(&hg[m_page->pids_idx].lock);

	cur_idx = hg_get_idx(m_page->accesses);
	m_page->hg_idx = cur_idx;

	update_page_list_with_mpage(m_page);

	spin_lock(&hg[m_page->pids_idx].lock);

	hg[m_page->pids_idx].hg[prev_idx]--;
	hg[m_page->pids_idx].hg[cur_idx]++;
	hg[m_page->pids_idx].nr_sampled++;

	spin_unlock(&hg[m_page->pids_idx].lock);
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
	spin_unlock(&f_pages[mtc->nid].lock);

	if (m_page) {
		page = m_page->page;
		reserve_page(h, mtc->nid, mtc->pid, m_page);
		sync_mtat_page_after_migration(mtc, m_page);
	}

	return page;
}

static unsigned int migrate_page_list(struct list_head *page_list, int nid, int pid, int hotness)
{
	unsigned int nr_migrated_pages = 0;
	struct page *page;
	struct page *page2;

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

	spin_lock(&debug_lock);
	debug_nr_migrated += nr_migrated_pages * 4 / 1024; // 4KB pages -> MB
	spin_unlock(&debug_lock);

	return nr_migrated_pages;
}

static unsigned int isolate_mtat_pages(struct page_list *from, 
		struct list_head *to, int target_nr)
{
	struct mtat_page *m_page = NULL;
	int nr = 0;

	if (target_nr == 0)
		return 0;

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

static void calculate_migration_target_size(int *target_promote,
		int *target_demote, int pid_idx, int dram_size)
{
	int nr_fmem[NR_HOTNESS_TYPES], nr_smem[NR_HOTNESS_TYPES];
	int dram_leftover, nr_need_demote = 0, total_dram_size = 0;
	int i;
	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		nr_fmem[i] = get_num_pages(&mtat_pages[i][pid_idx][FASTMEM]);
		nr_smem[i] = get_num_pages(&mtat_pages[i][pid_idx][SLOWMEM]);
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

static void solorun_migration(void)
{
	struct list_head promote_pages[NR_HOTNESS_TYPES];
	struct list_head demote_pages[NR_HOTNESS_TYPES];
	int target_promote[NR_HOTNESS_TYPES], target_demote[NR_HOTNESS_TYPES]; 
	int i;

	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		INIT_LIST_HEAD(&promote_pages[i]);
		INIT_LIST_HEAD(&demote_pages[i]);

	}

	calculate_migration_target_size(target_promote, target_demote, 0, set_lc_dram_size);

	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		isolate_mtat_pages(&mtat_pages[i][0][SLOWMEM], &promote_pages[i], target_promote[i]);
		isolate_mtat_pages(&mtat_pages[i][0][FASTMEM], &demote_pages[i], target_demote[i]);
	}

	for (i = NR_HOTNESS_TYPES-1; i >= 0; i--) 
		migrate_page_list(&demote_pages[i], SLOWMEM, pids[0], i);

	for (i = 0; i < NR_HOTNESS_TYPES; i++)
		migrate_page_list(&promote_pages[i], FASTMEM, pids[0], i);	
}

/*
 * LC: pids[0], BE: pids[1]
 * LC hot page는 모두 FMEM에 이주
 * LC FMEM cold page는 warm set size 만큼만 남기고 나머지 다 SMEM에 이주
 * FMEM이 남으면 BE의 SMEM page들을 FMEM에 이주 (hot page를 우선적으로)
 */
static void corun_migration(void)
{
	struct list_head promote_pages[2][NR_HOTNESS_TYPES]; // [lc/be]
	struct list_head demote_pages[2][NR_HOTNESS_TYPES]; // [lc/be]
	const int lc = 0, be = 1;
	int lc_target_promote[NR_HOTNESS_TYPES], lc_target_demote[NR_HOTNESS_TYPES]; 
	int be_target_promote[NR_HOTNESS_TYPES], be_target_demote[NR_HOTNESS_TYPES]; 
	int i, j;

	for (i = 0; i < 2; i++) {
		for (j = 0; j < NR_HOTNESS_TYPES; j++) {
			INIT_LIST_HEAD(&promote_pages[i][j]);
			INIT_LIST_HEAD(&demote_pages[i][j]);
		}
	}

	calculate_migration_target_size(lc_target_promote, lc_target_demote, 0, set_lc_dram_size);
	calculate_migration_target_size(be_target_promote, be_target_demote, 1, 
									total_dram_pages - set_lc_dram_size);

	/* Isolate pages for migration */
	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		isolate_mtat_pages(&mtat_pages[i][be][SLOWMEM], &promote_pages[be][i], be_target_promote[i]);
		isolate_mtat_pages(&mtat_pages[i][be][FASTMEM], &demote_pages[be][i], be_target_demote[i]);

		isolate_mtat_pages(&mtat_pages[i][lc][SLOWMEM], &promote_pages[lc][i], lc_target_promote[i]);
		isolate_mtat_pages(&mtat_pages[i][lc][FASTMEM], &demote_pages[lc][i], lc_target_demote[i]);
	}

	/* Do Migration */
	for (i = NR_HOTNESS_TYPES-1; i >= 0; i--) {
		migrate_page_list(&demote_pages[be][i], SLOWMEM, pids[be], i);
		migrate_page_list(&demote_pages[lc][i], SLOWMEM, pids[lc], i);
	}
	for (i = 0; i < NR_HOTNESS_TYPES; i++) {
		migrate_page_list(&promote_pages[lc][i], FASTMEM, pids[lc], i);	
		migrate_page_list(&promote_pages[be][i], FASTMEM, pids[be], i);	
	}
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
	}
}

static void update_histogram(void)
{
	hg_update_hot_threshold(0, set_lc_dram_size);
	if (MTAT_MIGRATION_MODE == CORUN)
		hg_update_hot_threshold(1, total_dram_pages - set_lc_dram_size);
}

static int kmigrated_main(void *data)
{
	int i, tmp;
	pr_info("kmigrated start\n");

	mtat_set_cpu_affinity(KMIGRATED_CPU);

	while (!kthread_should_stop()) {
		update_histogram();

		if (migrate_on) {
			do_migration();
		}

		lc_dram_pages = 0;
		lc_total_pages = 0;
		for (i = 0; i < NR_HOTNESS_TYPES; i++) {
			tmp = get_num_pages(&mtat_pages[i][0][FASTMEM]);
			lc_dram_pages += tmp;
			lc_total_pages += tmp + get_num_pages(&mtat_pages[i][0][SLOWMEM]);
		}

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
static struct task_struct *kcoolingd;

static int kcoolingd_main(void *data)
{
	uint64_t tmp_hg[16];
	int i;
	pr_info("kcoolingd start\n");

	mtat_set_cpu_affinity(KMIGRATED_CPU);

	while (!kthread_should_stop()) {
		spin_lock(&hg[0].lock);
		for (i = 0; i < 16; i++)
			tmp_hg[i] = hg[0].hg[i];
		spin_unlock(&hg[0].lock);

		spin_lock(&debug_lock);
		for (i = 0; i < 16; i++)
			lc_hg[i] = tmp_hg[i];
		spin_unlock(&debug_lock);

		partial_cooling();
		msleep(cooling_period);
		if (need_resched())
			schedule();
	}
	pr_info("kcoolingd exit\n");
	return 0;
}

/*
 * MTAT initialization
 */
int init_module(void)
{
	int cpu;

	FASTMEM = memory_nodes[0];
	SLOWMEM = memory_nodes[1];

	if (init_hashtable())
		return -1;

	init_hg();
	if (sysfs_create_file(kernel_kobj, &lc_hg_attr.attr)) {
		pr_info("failed to create sysfs entry for lc_hg\n");
		return -1;
	}
	if (sysfs_create_file(kernel_kobj, &lc_nr_sampled_attr.attr)) {
		pr_info("failed to create sysfs entry for lc_nr_sampled\n");
		return -1;
	}
	if (sysfs_create_file(kernel_kobj, &lc_nr_read_attr.attr)) {
		pr_info("failed to create sysfs entry for lc_nr_read\n");
		return -1;
	}
	if (sysfs_create_file(kernel_kobj, &lc_nr_dram_read_attr.attr)) {
		pr_info("failed to create sysfs entry for lc_nr_dram_read\n");
		return -1;
	}
	if (sysfs_create_file(kernel_kobj, &lc_nr_smem_read_attr.attr)) {
		pr_info("failed to create sysfs entry for lc_nr_smem_read\n");
		return -1;
	}
	build_page_list();

	set_dequeue_hook(mtat_allocate_page);
	set_enqueue_hook(mtat_free_page);

	/* pebs init */
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
	int cpu;

	if (kcoolingd)
		kthread_stop(kcoolingd);
	if (kmigrated)
		kthread_stop(kmigrated);
	if (kdebugd)
		kthread_stop(kdebugd);

	/* pebs stop */ 
	pebs_stop();

	set_dequeue_hook(NULL);
	set_enqueue_hook(NULL);

	destroy_hashtable();
	
	sysfs_remove_file(kernel_kobj, &lc_hg_attr.attr);
	sysfs_remove_file(kernel_kobj, &lc_nr_sampled_attr.attr);
	sysfs_remove_file(kernel_kobj, &lc_nr_read_attr.attr);
	sysfs_remove_file(kernel_kobj, &lc_nr_dram_read_attr.attr);
	sysfs_remove_file(kernel_kobj, &lc_nr_smem_read_attr.attr);

	pr_info("Remove MTAT module\n");
}

MODULE_AUTHOR("Minho Kim <mhkim@dgist.ac.kr>");
MODULE_DESCRIPTION("Multi-Tenant-Aware Tiered Memory Management");
MODULE_LICENSE("GPL v2");
