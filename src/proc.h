#define PROC_MAX_LINE 1024
#define SLABINFO "/proc/slabinfo"
#define SLABINFO_DEBUG_HEAD "slabinfo - version: 2.1 (statistics)\n"
#define SLABINFO_HEAD "slabinfo - version: 2.1\n"
#define SLAB_NAME_LEN 18

#define ZONEINFO "/proc/zoneinfo"
#define ZONENAMELEN 32

// For non debug case
struct slab_info {
	char name[SLAB_NAME_LEN];
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned int objsize;
	unsigned int objperslab;
	unsigned int pagesperslab;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int sharedfactor;
	unsigned long active_slabs;
	unsigned long num_slabs;
	unsigned long sharedavail;
};

struct zone_info {
	char name[ZONENAMELEN];
	int node;
	unsigned long free;
	unsigned long min;
	unsigned long low;
	unsigned long high;
	unsigned long spanned;
	unsigned long present;
	unsigned long managed;
	unsigned long start_pfn;
	unsigned long nr_free_pages;
	unsigned long nr_zone_inactive_anon;
	unsigned long nr_zone_active_anon;
	unsigned long nr_zone_inactive_file;
	unsigned long nr_zone_active_file;
	unsigned long nr_zone_unevictable;
	unsigned long nr_mlock;
	unsigned long nr_page_table_pages;
	unsigned long nr_kernel_stack;

	struct zone_info *next_zone;
};

int print_slab_usage(void);
int parse_zone_info(struct zone_info **zone);
