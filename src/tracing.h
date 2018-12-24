#include "utils.h"
#ifndef _MEMORY_TRACER_TRACING_LIB

#define to_callsite(tracenode) ((struct Callsite*)tracenode)
#define to_task(tracenode) ((struct Task*)tracenode)
#define to_tracenode(node) ((struct TraceNode*)node)

extern struct HashMap TaskMap;

struct Record {
	unsigned int bytes_req;
	unsigned int bytes_req_peak;
	unsigned int bytes_alloc;
	unsigned int bytes_alloc_peak;
	unsigned int pages_alloc;
	unsigned int pages_alloc_peak;
};

struct TraceNode {
	union {
		struct TraceNode *parent;
		struct TraceNode *parent_callsite;
		struct TraceNode *parent_task;
	};
	union {
		struct Callsite *child_callsites;
		struct Task *child_tasks;
	};
	struct Record record;
};

struct Callsite {
	// Keep it the first element
	struct TraceNode tracenode;

	char *symbol;
	unsigned long addr;

	struct TreeNode node;
};

struct Task {
	// Keep it the first element
	struct TraceNode tracenode;

	char *task_name;
	int pid;

	struct HashNode node;
};

struct Event {
	char *event;
	int bytes_req;
	int bytes_alloc;
	int pages_alloc;
};

struct PageRecord {
	struct TraceNode *tracenode;
};

struct AllocRecord {
	unsigned long long addr;
	int bytes_req;
	int bytes_alloc;

	struct TraceNode *tracenode;

	struct TreeNode node;
};

struct Context {
	struct Task *task;
	struct Event event;
};

void update_record(struct Record *record, struct Event *event);

struct Callsite* get_child_callsite(struct TraceNode *root, char *symbol, unsigned long addr);
struct Callsite* insert_child_callsite(struct TraceNode *root, struct Callsite *src);
struct Callsite* get_or_new_child_callsite(struct TraceNode *root, char *callsite, unsigned long addr);

void record_mem_alloc(struct TraceNode *root, unsigned long addr, unsigned int bytes_req, unsigned int bytes_alloc);
void record_mem_free(unsigned long addr);

int compTask(const void *lht, const void *rht);
int hashTask(const void *task);

struct Task* get_task(struct HashMap *map, char* task_name, int pid);
struct Task* insert_task(struct HashMap *map, struct Task* task);
struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid);

void print_task(struct Task* task);
void print_all_tasks(struct HashMap *map);

#define _MEMORY_TRACER_TRACING_LIB 1

#endif /* ifndef _MEMORY_TRACER_TRACING_LIB */
