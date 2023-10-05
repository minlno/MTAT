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
#include <asm-generic/io.h>

#define PID_NONE -1
#define MAX_PIDS 8

enum hotness_types {
	HOT = 0,
	COLD = 1,
	NR_HOTNESS_TYPES
};

enum memory_types {
	FASTMEM = 0,
	SLOWMEM = 1,
	NR_MEM_TYPES
};

enum access_types {
	READ_MTAT = 0,
	WRITE_MTAT = 1,
	NR_ACCESS_TYPES
};

// physical page를 나타냄.
// list를 통해 할당되고 안되고를 표현.
// 또한 hot인지 cold인지도 list를 통해 표현함.
struct mtat_page {
	struct page *page;
	uint64_t pfn;
	uint64_t accesses[NR_ACCESS_TYPES];
	uint64_t local_clock;
	int hotness;
	int pids_idx;
	int nid;
	struct rhash_head node;
	struct list_head list;
	spinlock_t lock;
};

struct mtat_page *alloc_and_init_mtat_page(struct page *page);

struct page_list {
	struct list_head list;
	int num_pages;
	bool need_cooling;
	struct mtat_page *curr_cool_page;
	spinlock_t lock;
};

int get_num_pages(struct page_list *pl); 
bool need_cooling(struct page_list *pl);
void set_need_cooling(struct page_list *pl, bool cool);
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
	u64 phys_addr;
};
#define HOT_READ_THRESHOLD 8
#define HOT_WRITE_THRESHOLD 4
#define COOL_THRESHOLD 18
#define COOL_PAGES 8192
#define PMEM_READ 0x80d1
#define DRAM_READ 0x01d3
#define STORE_ALL 0x82d0
#define SAMPLE_PERIOD_PEBS 10007

/*
 * Migration
 */
enum migration_modes {
	SOLORUN,
	CORUN,
	HEMEM,
	TEST_MODE
};

//#define MTAT_MIGRATION_MODE SOLORUN
//#define MTAT_MIGRATION_MODE CORUN
#define MTAT_MIGRATION_MODE HEMEM
//#define MTAT_MIGRATION_MODE TEST_MODE
#define WARM_SET_SIZE 50 // 2MB page 갯수
#define ENABLE_MIGRATION 1
#define ENABLE_MONITOR 0

struct migration_target_control {
	int nid;
	int pid;
	int hotness;
};

#endif /* __MTAT__ */
