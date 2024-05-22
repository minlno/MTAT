#ifndef __MTAT__
#define __MTAT__

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/perf_event.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/cpumask.h>
#include <asm-generic/io.h>
/*
 * Debug
 */
#define KDEBUGD_CPU 50

struct mtat_debug_info {
	uint64_t nr_sampled[4];
	uint64_t nr_found;
	uint64_t nr_cooled;
	uint64_t nr_migrated;
	spinlock_t lock;
};

/*
 * App struct
 */
#define PID_NONE -1
#define MAX_APPS 8

struct access_histogram {
	uint64_t histogram[16];
	uint64_t hot_threshold;
	uint64_t warm_threshold;
	spinlock_t lock;
};

struct app_struct {
	int pid;

	/* lock 으로 보호 start */
	int _pids[MAX_APPS]; // for memtis
	uint64_t _dram_pages[MAX_APPS]; // for memtis
	uint64_t _total_pages[MAX_APPS]; // for memtis
	uint64_t _set_dram_size[MAX_APPS]; // for memtis

	uint64_t set_dram_size;
	// debug thread가 1초마다 업데이트. 즉, 1초동안 쌓인 샘플 수를 의미.
	uint64_t nr_total_sampled;
	uint64_t nr_fmem_read;
	uint64_t nr_smem_read;
	// migration thread가 1ms마다 업데이트. migration 할때마다 업데이트.
	uint64_t dram_pages; 
	uint64_t total_pages;
	// cooling thread가 1초마다 업데이트. 즉, 1초동안 쌓인 histogram을 의미.
	uint64_t fixed_hg[16];
	/* lock 으로 보호 end */
	spinlock_t lock;

	// 실시간으로 업데이트됨. 1초마다 초기화됨.
	struct mtat_debug_info debug;

	struct access_histogram hg;
};

enum hotness_types {
	HOT = 0,
	WARM = 1,
	COLD = 2,
	NR_HOTNESS_TYPES
};

#define CXL_MODE

// physical page를 나타냄.
// list를 통해 할당되고 안되고를 표현.
// 또한 hot인지 cold인지도 list를 통해 표현함.
struct mtat_page {
	struct page *page;
	uint64_t pfn;
	uint64_t accesses;
	int hotness;
	int apps_idx; 
	int nid;
	int hg_idx;
	struct rhash_head node;
	struct list_head list;
	struct list_head t_list;
	spinlock_t lock;
	int pids_idx; // for memtis
};

struct mtat_page *alloc_and_init_mtat_page(struct page *page);

struct page_list {
	struct list_head list;
	int num_pages;
	int num_pages_pid[MAX_APPS]; // for memtis
	spinlock_t lock;
};

int get_num_pages(struct page_list *pl); 
void page_list_del(struct mtat_page *m_page, struct page_list *list); // num_page 카운팅도 수행.
void page_list_add(struct mtat_page *m_page, struct page_list *list); // num_page 카운팅도 수행.
void init_page_list(struct page_list *list);


/*
 * PEBS sampling
 */
struct perf_sample {
	struct perf_event_header header;
	u64 ip;
	u32 pid, tid;
	u64 addr;
	u32 cpu, res;
};
#define PMEM_READ 0x80d1 // Optane
#define CXL_READ 0x02d3 // CXL
#define DRAM_READ 0x01d3
#define STORE_ALL 0x82d0
#define SAMPLE_PERIOD_PEBS 5003 // 10007 5003
#define KPEBSD_CPU 48

/*
 * Migration
 */
enum migration_modes {
	MTAT,
	HEMEM,
	MEMTIS
};

#define MTAT_MIGRATION_MODE MTAT
//#define MTAT_MIGRATION_MODE MEMTIS
//#define MTAT_MIGRATION_MODE HEMEM
//#define MTAT_MIGRATION_MODE TEST_MODE
#define KMIGRATED_CPU 49

struct migration_target_control {
	int nid;
	int pid;
	int hotness;
};

/*
 * Sysfs
 */
struct mtat_sysfs_memtis_dir {
	struct kobject kobj;
	int pids_idx;
};

struct mtat_sysfs_app_dir {
	struct kobject kobj;
	int app_idx;
	struct mtat_sysfs_memtis_dir memtis_dirs[MAX_APPS];
};

struct mtat_sysfs_apps_dir {
	struct kobject kobj;
	struct mtat_sysfs_app_dir app_dirs[MAX_APPS];
};

struct mtat_sysfs_ui_dir {
	struct kobject kobj;
	struct mtat_sysfs_apps_dir *apps_dir;
};


#endif /* __MTAT__ */
