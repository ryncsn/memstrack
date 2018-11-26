#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "utils.h"

struct Record {
	unsigned int bytes_req;
	unsigned int bytes_alloc;
	unsigned int pages_alloc;
};

struct TraceNode {
	char *callsite;
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

void update_record(struct Record *record, struct Event *event);
int compTraceNode(struct TreeNode *src, struct TreeNode *root);

struct TraceNode* get_tracepoint(struct TraceNode **root, char *callsite);
struct TraceNode* insert_tracepoint(struct TraceNode **root, struct TraceNode *src, char *callsite);
struct TraceNode* get_or_new_tracepoint(struct TraceNode **root, char *callsite);


int compTask(const void *lht, const void *rht);
int hashTask(const void *task);

struct Task* get_task(struct HashMap *map, char* task_name, int pid);
struct Task* insert_task(struct HashMap *map, struct Task* task);
struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid);


void print_tracenode(struct TreeNode* tnode);
void print_task_tracenode(struct TreeNode* tnode);
void print_task(struct Task* task);
void print_all_tasks(struct HashMap *map);
