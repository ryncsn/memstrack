#include "utils.h"
#ifndef _MEMORY_TRACER_TRACING_LIB

#define to_callsite(tracenode) ((struct Callsite*)tracenode)
#define to_task(tracenode) ((struct Task*)tracenode)
#define to_tracenode(node) ((struct TraceNode*)node)

extern struct HashMap TaskMap;

extern unsigned long trace_count;

struct Record {
	long pages_alloc;
	long pages_alloc_peak;
};

struct TraceNode {
	struct TraceNode *parent;
	// TODO: Only leaf have record,
	// union {
	struct Callsite *child_callsites;
	struct Record *record;
	// };
};

struct Callsite {
	struct TraceNode tracenode;
	struct TreeNode node;

	// TODO: Only keep symbol or addr
	// union {
		char *symbol;
		unsigned long addr;
	// };
};

struct Task {
	struct TraceNode tracenode;
	struct HashNode node;

	// TODO: Only keep pid or name
	// union {
	char *task_name;
	int pid;
	// };
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
void load_kallsyms();
char* kaddr_to_sym(unsigned long long addr);

struct Callsite* get_child_callsite(struct TraceNode *root, char *symbol, unsigned long addr);
struct Callsite* insert_child_callsite(struct TraceNode *root, struct Callsite *src);
struct Callsite* get_or_new_child_callsite(struct TraceNode *root, char *callsite, unsigned long addr);

struct Task* get_task(struct HashMap *map, char* task_name, int pid);
struct Task* insert_task(struct HashMap *map, struct Task* task);
struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid);

void final_report(struct HashMap *map, int task_limit);

#define _MEMORY_TRACER_TRACING_LIB 1

#endif /* ifndef _MEMORY_TRACER_TRACING_LIB */
