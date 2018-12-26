#include <stdint.h>
#include <unistd.h>
#include <linux/perf_event.h>

#define CPU_BUFSIZE 128


struct PerfEvent {
	int cpu;
	int perf_fd;
	int perf_id;
	int event_id;
	char* event_name;
	int (*sample_handler) (struct PerfEvent*, const unsigned char*, void *blob);

	void *mmap;
	unsigned long long mmap_size;
	unsigned long long data_size;
	unsigned long long index;
	unsigned long long counter;

	struct perf_event_attr *attr;

	unsigned char *data;
	struct perf_event_mmap_page *meta;
};

typedef int (*SampleHandler) (struct PerfEvent*, const unsigned char*, void *blob);

struct read_format {
	uint64_t value;			/* The value of the event */
	uint64_t time_enabled;		/* if PERF_FORMAT_TOTAL_TIME_ENABLED */
	uint64_t time_running;		/* if PERF_FORMAT_TOTAL_TIME_RUNNING */
	uint64_t id;			/* if PERF_FORMAT_ID */
};


struct read_format_group_hdr {
	uint64_t nr;			/* The number of events */
	uint64_t time_enabled;		/* if PERF_FORMAT_TOTAL_TIME_ENABLED */
	uint64_t time_running;		/* if PERF_FORMAT_TOTAL_TIME_RUNNING */
};

struct read_format_group_data {
	uint64_t value;			/* The value of the event */
	uint64_t id;			/* if PERF_FORMAT_ID */
};

// Remember to adjust structures blow if changed this config flag
#define SAMPLE_CONFIG_FLAG \
	PERF_SAMPLE_CPU | \
	PERF_SAMPLE_RAW | \
	PERF_SAMPLE_TID | \
	PERF_SAMPLE_CALLCHAIN

struct perf_sample_id {
	uint32_t pid;			/* if PERF_SAMPLE_TID set */
	uint32_t tid;			/* if PERF_SAMPLE_TID set */
//	u64 time;			/* if PERF_SAMPLE_TIME set */
//	u64 id;				/* if PERF_SAMPLE_ID set */
//	u64 stream_id;			/* if PERF_SAMPLE_STREAM_ID set	*/
	uint32_t cpu;			/* if PERF_SAMPLE_CPU set */
	uint32_t res;			/* if PERF_SAMPLE_CPU set */
//	u64 id;				/* if PERF_SAMPLE_IDENTIFIER set */
};

struct perf_lost_events {
	struct perf_event_header header;
	uint64_t	id;
	uint64_t	lost;
	struct perf_sample_id sample_id;
};

// corresponding part of a perf sample
struct perf_sample_fix {
	struct perf_event_header header;
//	uint64_t sample_id;		/* if PERF_SAMPLE_IDENTIFIER */
//	uint64_t ip;			/* if PERF_SAMPLE_IP */
	uint32_t pid, tid;		/* if PERF_SAMPLE_TID */
//	uint64_t time;			/* if PERF_SAMPLE_TIME */
//	uint64_t addr;			/* if PERF_SAMPLE_ADDR */
//	uint64_t id;			/* if PERF_SAMPLE_ID */
//	uint64_t stream_id;		/* if PERF_SAMPLE_STREAM_ID */
	uint32_t cpu, res;		/* if PERF_SAMPLE_CPU */
//	uint64_t period;		/* if PERF_SAMPLE_PERIOD */
//	struct read_format v;		/* if PERF_SAMPLE_READ */
};

struct perf_sample_callchain {
	uint64_t nr;			/* if PERF_SAMPLE_CALLCHAIN */
	uint64_t ips;			/* if PERF_SAMPLE_CALLCHAIN */
};

struct perf_sample_raw {
	uint32_t size;			/* if PERF_SAMPLE_RAW */
	char data;			/* if PERF_SAMPLE_RAW */
};

struct perf_sample__unused {
// 	uint64_t bnr;				/* if PERF_SAMPLE_BRANCH_STACK */
// 	struct perf_branch_entry lbr[bnr];	/* if PERF_SAMPLE_BRANCH_STACK */
// 	uint64_t abi;				/* if PERF_SAMPLE_REGS_USER */
// 	uint64_t regs[weight(mask)];		/* if PERF_SAMPLE_REGS_USER */
// 	uint64_t size;				/* if PERF_SAMPLE_STACK_USER */
// 	char data[size];			/* if PERF_SAMPLE_STACK_USER */
// 	uint64_t dyn_size;			/* if PERF_SAMPLE_STACK_USER && size != 0 */
// 	uint64_t weight;			/* if PERF_SAMPLE_WEIGHT */
// 	uint64_t data_src;			/* if PERF_SAMPLE_DATA_SRC */
// 	uint64_t transaction;			/* if PERF_SAMPLE_TRANSACTION */
// 	uint64_t abi;				/* if PERF_SAMPLE_REGS_INTR */
// 	uint64_t regs[weight(mask)];		/* if PERF_SAMPLE_REGS_INTR */
};

// TODO: read from /sys/kernel/debug/tracing/events/*/*/format to get format
// XXX: only for x86_64
struct perf_raw_mm_page_alloc {
	/*
	 * field:unsigned short common_type;       offset:0;       size:2; signed:0;
	 * field:unsigned char common_flags;       offset:2;       size:1; signed:0;
	 * field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
	 * field:int common_pid;   offset:4;       size:4; signed:1;

	 * field:unsigned long pfn;        offset:8;       size:8; signed:0;
	 * field:unsigned int order;       offset:16;      size:4; signed:0;
	 * field:gfp_t gfp_flags;  offset:20;      size:4; signed:0;
	 * field:int migratetype;  offset:24;      size:4; signed:1;
	 */
	uint16_t common_type;
	uint8_t common_flag;
	uint8_t common_preempt_count;
	int32_t common_pid;

	uint64_t pfn;
	uint32_t order;
	uint32_t gfp_flags;
	int32_t migratetype;

	uint8_t _reserved[8];
};

struct perf_raw_mm_page_zone_locked {
	/*
	 * field:unsigned short common_type;       offset:0;       size:2; signed:0;
	 * field:unsigned char common_flags;       offset:2;       size:1; signed:0;
	 * field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
	 * field:int common_pid;   offset:4;       size:4; signed:1;

	 * field:unsigned long pfn;        offset:8;       size:8; signed:0;
	 * field:unsigned int order;       offset:16;      size:4; signed:0;
	 * field:int migratetype;  offset:20;      size:4; signed:1;
	 */
	uint16_t common_type;
	uint8_t common_flag;
	uint8_t common_preempt_count;
	int32_t common_pid;

	uint64_t pfn;
	uint32_t order;
	int32_t migratetype;

	uint8_t _reserved[8];
};

struct perf_raw_mm_page_free {
	/*
         * field:unsigned short common_type;       offset:0;       size:2; signed:0;
         * field:unsigned char common_flags;       offset:2;       size:1; signed:0;
         * field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
         * field:int common_pid;   offset:4;       size:4; signed:1;

         * field:unsigned long pfn;        offset:8;       size:8; signed:0;
         * field:unsigned int order;       offset:16;      size:4; signed:0;
	 */
	uint16_t common_type;
	uint8_t common_flag;
	uint8_t common_preempt_count;
	int32_t common_pid;

	uint64_t pfn;
	uint32_t order;

	uint8_t _reserved[8];
};

struct perf_raw_kmem_cache_alloc {
	/*
         * field:unsigned short common_type;       offset:0;       size:2; signed:0;
         * field:unsigned char common_flags;       offset:2;       size:1; signed:0;
         * field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
         * field:int common_pid;   offset:4;       size:4; signed:1;

         * field:unsigned long call_site;  offset:8;       size:8; signed:0;
         * field:const void * ptr; offset:16;      size:8; signed:0;
         * field:size_t bytes_req; offset:24;      size:8; signed:0;
         * field:size_t bytes_alloc;       offset:32;      size:8; signed:0;
         * field:gfp_t gfp_flags;  offset:40;      size:4; signed:0;
	 */

	uint16_t common_type;
	uint8_t common_flag;
	uint8_t common_preempt_count;
	int32_t common_pid;

	uint64_t call_site;
	uint64_t ptr;
	uint64_t bytes_req;
	uint64_t bytes_alloc;
	uint32_t gfp_flags;

	uint8_t _reserved[8];
};

struct perf_raw_kmem_cache_free {
	/*
         * field:unsigned short common_type;       offset:0;       size:2; signed:0;
         * field:unsigned char common_flags;       offset:2;       size:1; signed:0;
         * field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
         * field:int common_pid;   offset:4;       size:4; signed:1;

         * field:unsigned long call_site;  offset:8;       size:8; signed:0;
         * field:const void * ptr; offset:16;      size:8; signed:0;
	 */

	uint16_t common_type;
	uint8_t common_flag;
	uint8_t common_preempt_count;
	int32_t common_pid;

	uint64_t call_site;
	uint64_t ptr;

	uint8_t _reserved[8];
};

struct perf_raw_kmalloc {
	/*
	 * field:unsigned short common_type;       offset:0;       size:2; signed:0;
         * field:unsigned char common_flags;       offset:2;       size:1; signed:0;
         * field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
         * field:int common_pid;   offset:4;       size:4; signed:1;

         * field:unsigned long call_site;  offset:8;       size:8; signed:0;
         * field:const void * ptr; offset:16;      size:8; signed:0;
         * field:size_t bytes_req; offset:24;      size:8; signed:0;
         * field:size_t bytes_alloc;       offset:32;      size:8; signed:0;
         * field:gfp_t gfp_flags;  offset:40;      size:4; signed:0;
	 */

	uint16_t common_type;
	uint8_t common_flag;
	uint8_t common_preempt_count;
	int32_t common_pid;

	uint64_t call_site;
	uint64_t ptr;
	uint64_t bytes_req;
	uint64_t bytes_alloc;
	uint32_t gfp_flags;

	uint8_t _reserved[8];
};

struct perf_raw_kfree {
	/*
         * field:unsigned short common_type;       offset:0;       size:2; signed:0;
         * field:unsigned char common_flags;       offset:2;       size:1; signed:0;
         * field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
         * field:int common_pid;   offset:4;       size:4; signed:1;

         * field:unsigned long call_site;  offset:8;       size:8; signed:0;
         * field:const void * ptr; offset:16;      size:8; signed:0;
	 */

	uint16_t common_type;
	uint8_t common_flag;
	uint8_t common_preempt_count;
	int32_t common_pid;

	uint64_t call_site;
	uint64_t ptr;

	uint8_t _reserved[8];
};

int get_perf_cpu_num();
unsigned int get_perf_event_id(const char*);

int perf_event_setup(struct PerfEvent *perf_event);
int perf_event_start_sampling(struct PerfEvent *perf_event);
int perf_event_process(struct PerfEvent *perf_event, void *blob);
int perf_event_clean(struct PerfEvent *perf_event);
