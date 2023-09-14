#include "mtat.h"

static int pids[MAX_PIDS];
static int num_pages[MAX_PIDS][NR_MEM_TYPES][NR_HOTNESS_TYPES];
static struct list_head f_pages[NR_MEM_TYPES]; // free_pages
static struct list_head hot_pages[MAX_PIDS][NR_MEM_TYPES];
static struct list_head cold_pages[MAX_PIDS][NR_MEM_TYPES];
static spinlock_t lock;

static struct rhashtable *hashtable = NULL;
static struct rhashtable_params params = {
	.head_offset = offsetof(struct mtat_page, node),
	.key_offset = offsetof(struct mtat_page, pfn),
	.key_len = sizeof(uint64_t),
	.automatic_shrinking = false,
	.min_size = 0xffff,
};

static void print_num_pages(void)
{
	static int z = 0;
	int i, j, k;

	z++;
	if (z % 500 != 0)
		return;
	z = 0;

	for (i = 0; i < MAX_PIDS; i++) {
		if (pids[i] == PID_NONE)
			continue;
		pr_info("pid: %d\n", pids[i]);
		for (j = 0; j < NR_MEM_TYPES; j++) {
			pr_info("numa node: %d\n", j);
			for (k = 0; k < NR_HOTNESS_TYPES; k++) {
				if (k == HOT)
					pr_info("hot_pages: %d\n", num_pages[i][j][k]);
				else
					pr_info("cold_pages: %d\n", num_pages[i][j][k]);
			}
		}
	}
}

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

static int add_new_page(struct page *page)
{
	int i, err;
	struct mtat_page *m_page = kmalloc(sizeof(*m_page), GFP_KERNEL);
	if (!m_page) {
		pr_err("Failed to allocate mtat_page\n");
		return -1;
	}

	m_page->page = page;
	m_page->pfn = page_to_pfn(page);
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
	uint64_t pfn = page_to_pfn(page);
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

	m_page->hotness = COLD;
	m_page->pids_idx = i;
	pids[i] = pid;
	list_move(&m_page->list, &cold_pages[i][nid]);
	num_pages[i][nid][COLD]++;

	print_num_pages();

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

	pr_info("Successfully insert MTAT module\n");
	return 0;
}

void cleanup_module(void)
{
	destroy_hashtable();

	set_dequeue_hook(NULL);
	set_enqueue_hook(NULL);

	pr_info("Remove MTAT module\n");
}

MODULE_AUTHOR("Minho Kim <mhkim@dgist.ac.kr>");
MODULE_DESCRIPTION("Multi-Tenant-Aware Tiered Memory Management");
MODULE_LICENSE("GPL v2");
