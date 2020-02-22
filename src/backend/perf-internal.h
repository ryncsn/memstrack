#include <linux/perf_event.h>

struct PerfEventField {
	char *name;
	char *type;

	short size;
	short offset;
	short is_signed;
	short checked;
};

struct PerfEvent {
	char *event_class;
	char *name;
	int id;

	short fileds_num;

	struct PerfEventField fields[];
};

struct PerfEventRing {
	int cpu;
	int fd;

	struct PerfEvent *event;

	int (*sample_handler) (struct PerfEventRing*, const unsigned char*);

	void *mmap;
	unsigned char *data;
	unsigned long long mmap_size;
	unsigned long long data_size;
	unsigned long long index;
	unsigned long long counter;

	struct perf_event_mmap_page *meta;
};

typedef int (*SampleHandler) (struct PerfEvent*, const unsigned char*);

struct perf_event_table_entry {
	struct PerfEvent *event;
	int (*handler)(struct PerfEventRing *ring, const unsigned char* header);
	int (*is_enabled)(void);
};

extern const struct perf_event_table_entry perf_event_table[];

extern const int perf_event_entry_number;

int perf_load_events(void);
int perf_ring_setup(struct PerfEventRing *ring);
int perf_ring_start_sampling(struct PerfEventRing *ring);
int perf_ring_process(struct PerfEventRing *ring);
int perf_ring_clean(struct PerfEventRing *ring);

int perf_get_cpu_num(void);
int perf_do_load_event_info(struct PerfEvent *entry);

int sys_perf_event_open(struct perf_event_attr *attr,
		int pid, int cpu, int group_fd,
		unsigned long flags);
