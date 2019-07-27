#define SLABINFO "/proc/slabinfo"
#define SLABINFO_DEBUG_HEAD "slabinfo - version: 2.1 (statistics)\n"
#define SLABINFO_HEAD "slabinfo - version: 2.1\n"
#define SLAB_NAME_LEN 32

// For non debug case
struct slab_entry {
	char *name;
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned int objsize;
	unsigned int objperslab;
	unsigned int pagesperslab;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int sharedfactor;
	unsigned int active_slabs;
	unsigned int num_slabs;
	unsigned int sharedavail;
};

int print_slab_usage(void);
