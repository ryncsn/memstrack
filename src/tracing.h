#include "utils.h"
#ifndef _MEMORY_TRACER_TRACING_LIB

#define to_callsite(tracenode) ((struct Callsite*)tracenode)
#define to_task(tracenode) ((struct Task*)tracenode)
#define to_tracenode(node) ((struct TraceNode*)node)

extern struct HashMap TaskMap;

struct Record {
	long pages_alloc;
	long pages_alloc_peak;
};

struct TraceNode {
	union {
		struct TraceNode *parent;
		struct TraceNode *parent_callsite;
		struct TraceNode *parent_task;
	};
	union {
		struct Task *child_tasks;
		struct Callsite *child_callsites;
	};
	struct Record *record;
};

struct Callsite {
	struct TraceNode tracenode;
	struct TreeNode node;

	char *symbol;
	unsigned long addr;
};

struct Task {
	struct TraceNode tracenode;
	struct HashNode node;

	char *task_name;
	int pid;
};

struct PageRecord {
	struct TraceNode *tracenode;
};

struct AllocRecord {
	struct TreeNode node;
	struct TraceNode *tracenode;

	unsigned long long addr;
	unsigned long size;
};

struct AllocEvent {
	unsigned long kvaddr;
	long bytes_req;
	long bytes_alloc;
};

struct PageEvent {
	unsigned long pfn;
	long pages_alloc;
};

void mem_tracing_init();
void update_record(struct TraceNode *record, struct PageEvent *pe, struct AllocEvent *ae);

struct Callsite* get_child_callsite(struct TraceNode *root, char *symbol, unsigned long addr);
struct Callsite* insert_child_callsite(struct TraceNode *root, struct Callsite *src);
struct Callsite* get_or_new_child_callsite(struct TraceNode *root, char *callsite, unsigned long addr);

struct Task* get_task(struct HashMap *map, char* task_name, int pid);
struct Task* insert_task(struct HashMap *map, struct Task* task);
struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid);

void final_report(struct HashMap *map, int task_limit);

#define _MEMORY_TRACER_TRACING_LIB 1

#endif /* ifndef _MEMORY_TRACER_TRACING_LIB */
