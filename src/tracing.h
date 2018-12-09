#include "utils.h"
#ifndef _MEMORY_TRACER_TRACING_LIB

extern struct HashMap TaskMap;

struct Record {
	unsigned int bytes_req;
	unsigned int bytes_alloc;
	unsigned int pages_alloc;
};

struct TraceNode {
	char *callsite;
	unsigned long long callsite_addr;
	struct Record record;
	struct TraceNode *tracepoints;

	struct TreeNode node;
};

struct Task {
	int pid;
	char *task_name;
	struct Record record;
	struct TraceNode *tracepoints;

	struct HashNode node;
};

struct Event {
	char *event;
	int bytes_req;
	int bytes_alloc;
	int pages_alloc;
};

struct Context {
	struct Task *task;
	struct Event event;
};

void update_record(struct Record *record, struct Event *event);
int compTraceNodeResolved(struct TreeNode *src, struct TreeNode *root);
int compTraceNodeRaw(struct TreeNode *src, struct TreeNode *root);

struct TraceNode* get_tracepoint(struct TraceNode **root, char *callsite);
struct TraceNode* insert_tracepoint(struct TraceNode **root, struct TraceNode *src);
struct TraceNode* get_or_new_tracepoint(struct TraceNode **root, char *callsite);

struct TraceNode* get_tracepoint_raw(struct TraceNode **root, unsigned long long callsite);
struct TraceNode* insert_tracepoint_raw(struct TraceNode **root, struct TraceNode *src);
struct TraceNode* get_or_new_tracepoint_raw(struct TraceNode **root, unsigned long long callsite);

int compTask(const void *lht, const void *rht);
int hashTask(const void *task);

struct Task* get_task(struct HashMap *map, char* task_name, int pid);
struct Task* insert_task(struct HashMap *map, struct Task* task);
struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid);

void print_task(struct Task* task);
void print_all_tasks(struct HashMap *map);

#define _MEMORY_TRACER_TRACING_LIB 1

#endif /* ifndef _MEMORY_TRACER_TRACING_LIB */
