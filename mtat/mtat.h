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

#define PID_NONE -1
#define MAX_PIDS 8

enum hotness_types {
	HOT = 0,
	WARM = 1,
	COLD = 2,
	NR_HOTNESS_TYPES
};

#define CXL_MODE

struct access_histogram {
	uint64_t hg[16];
	spinlock_t lock;

	uint64_t nr_sampled;
	uint64_t hot_threshold;
	uint64_t warm_threshold;
};

// physical page를 나타냄.
// list를 통해 할당되고 안되고를 표현.
// 또한 hot인지 cold인지도 list를 통해 표현함.
struct mtat_page {
	struct page *page;
	uint64_t pfn;
	uint64_t accesses;
	int hotness;
	int pids_idx;
	int nid;
	int hg_idx;
	struct rhash_head node;
	struct list_head list;
	struct list_head t_list;
	spinlock_t lock;
};

struct mtat_page *alloc_and_init_mtat_page(struct page *page);

struct page_list {
	struct list_head list;
	int num_pages;
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
#define COOL_PAGES 8192
#define PMEM_READ 0x80d1 // Optane
#define CXL_READ 0x02d3 // CXL
#define DRAM_READ 0x01d3
#define STORE_ALL 0x82d0
#define SAMPLE_PERIOD_PEBS 5003 // 10007
#define KPEBSD_CPU 4

/*
 * Migration
 */
enum migration_modes {
	SOLORUN,
	CORUN
};

//#define MTAT_MIGRATION_MODE SOLORUN
#define MTAT_MIGRATION_MODE CORUN // LC, BE 순으로 실행해야함.
//#define MTAT_MIGRATION_MODE HEMEM
//#define MTAT_MIGRATION_MODE TEST_MODE
#define KMIGRATED_CPU 5

struct migration_target_control {
	int nid;
	int pid;
	int hotness;
};

/*
 * Debug
 */
#define KDEBUGD_CPU 6

#endif /* __MTAT__ */
