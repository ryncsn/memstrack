#include "utils.h"
#ifndef _MEMORY_TRACER_TRACING_LIB

#define to_tracenode(task_p) (&task_p->tracenode)
#define is_task(tracenode_p) (tracenode_p->parent == NULL)
#define is_stacktop(tracenode_p) (tracenode_p->children == NULL)
// TODO: Remove redundant record, and when alloc happened extending a stacktop, remove old record and inherit.

typedef void* trace_addr_t;

extern struct HashMap task_map;

extern unsigned long trace_count;
extern unsigned long page_alloc_counter, page_free_counter;

struct Record {
	unsigned long addr;

	long pages_alloc;
	long pages_alloc_peak;

	void *blob;
};

struct Tracenode {
	/* Tree node linking all neibors */
	struct TreeNode node;
	struct Tracenode *parent;
	struct Tracenode *children;

	union {
		trace_addr_t addr;
		char* symbol;

		void* key;
	};

	struct Record *record;
};

struct Task {
	struct HashNode node;
	struct Tracenode tracenode;

	// TODO: Distinguish exited task, loop pid
	long pid;
	char *task_name;
};

struct PageRecord {
	struct Tracenode *tracenode;
};

struct AllocRecord {
	struct TreeNode node;
	struct Tracenode *tracenode;

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
void update_record(struct Tracenode *record, struct PageEvent *pe);
void try_update_record(struct Tracenode *record, struct PageEvent *pe);
void load_kallsyms();
void store_symbol_instead(void);
char* kaddr_to_sym(trace_addr_t addr);
char* kaddr_to_module(trace_addr_t addr);
char* get_tracenode_symbol(struct Tracenode *node);

void populate_tracenode_shallow(struct Tracenode* tracenode);
void populate_tracenode(struct Tracenode* tracenode);
void depopulate_tracenode(struct Tracenode* tracenode);

struct Tracenode* get_child_tracenode(struct Tracenode *root, void *key);
struct Tracenode* get_or_new_child_tracenode(struct Tracenode *root, void *key);
struct Task* get_task(struct HashMap *map, char* task_name, int pid);
struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid);
struct Task **collect_tasks_sorted(struct HashMap *map, int shallow);
struct Tracenode **collect_tracenodes_sorted(struct Tracenode *root, int *counter, int shallow);

void final_report(struct HashMap *map, int task_limit);
int for_each_tracenode_ret(struct Tracenode* root, int (*op)(struct Tracenode *node, void *blob), void *blob);
void for_each_tracenode(struct Tracenode* root, void (*op)(struct Tracenode *node, void *blob), void *blob);

#define _MEMORY_TRACER_TRACING_LIB 1

#endif /* ifndef _MEMORY_TRACER_TRACING_LIB */
