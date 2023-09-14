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

#define PID_NONE -1
#define MAX_PIDS 4

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
	int hotness;
	int pids_idx;

	struct rhash_head node;
	struct list_head list;
};
