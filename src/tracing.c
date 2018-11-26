#include "tracing.h"

void update_record(struct Record *record, struct Event *event) {
	record->bytes_req += event->bytes_req;
	record->bytes_alloc += event->bytes_alloc;
	record->pages_alloc += event->pages_alloc;
}

int compTraceNode(struct TreeNode *src, struct TreeNode *root) {
	struct TraceNode *src_data = get_node_data(src, struct TraceNode, node);
	struct TraceNode *root_data = get_node_data(root, struct TraceNode, node);
	return strcmp(src_data->callsite, root_data->callsite);
}

struct TraceNode* get_tracepoint(struct TraceNode **root, char *callsite){
	if (*root == NULL)
		return NULL;

	struct TreeNode *rnode = &((*root)->node), *tnode = NULL;
	struct TraceNode temp_node = {callsite};
	tnode = get_tree_node(&rnode, &temp_node.node, compTraceNode);
	*root = get_node_data
		(rnode,
		 struct TraceNode,
		 node);
	if (tnode) {
		return get_node_data
			(tnode,
			 struct TraceNode,
			 node);
	} else {
		return NULL;
	}
}

struct TraceNode* insert_tracepoint(struct TraceNode **root, struct TraceNode *src, char *callsite){
	if (*root == NULL) {
		return *root = src;
	}
	struct TreeNode *rnode = &((*root)->node);
	insert_tree_node(&rnode, &src->node, compTraceNode);
	*root = get_node_data
		(rnode,
		 struct TraceNode,
		 node);
	assert(*root = src);
	return get_node_data
		(rnode,
		 struct TraceNode,
		 node);
}

struct TraceNode* get_or_new_tracepoint(struct TraceNode **root, char *callsite){
	struct TraceNode *tracepoint = get_tracepoint(root, callsite);
	if (tracepoint == NULL) {
		int callsite_len = strlen(callsite) + 1;
		tracepoint = (struct TraceNode*)calloc(1, sizeof(struct TraceNode));
		tracepoint->callsite = (char*)malloc(callsite_len);
		strcpy(tracepoint->callsite, callsite);
		insert_tracepoint(root, tracepoint, callsite);
		return tracepoint;
	} else {
		return tracepoint;
	}
}

int compTask(const void *lht, const void *rht) {
	if (((struct Task*)lht)->pid != ((struct Task*)rht)->pid) {
		return ((struct Task*)lht)->pid - ((struct Task*)rht)->pid;
	} else {
		return strcmp(((struct Task*)lht)->task_name, ((struct Task*)rht)->task_name);
	}
}

int hashTask(const void *task) {
	return ((struct Task*)task)->pid;
}

struct Task* get_task(struct HashMap *map, char* task_name, int pid) {
	struct Task tmp_task = {pid, task_name};
	struct HashNode *hnode = get_hash_node(map, &tmp_task);
	if (hnode) {
		return get_node_data(
				hnode,
				struct Task,
				node);
	} else {
		return NULL;
	}
};

struct Task* insert_task(struct HashMap *map, struct Task* task) {
	return get_node_data
		(insert_hash_node(map, &task->node, task),
		 struct Task,
		 node);
};

struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid) {
	struct Task *task = get_task(map, task_name, pid);
	if (task == NULL) {
		int task_name_len = strlen(task_name) + 1;
		task = (struct Task*)calloc(1, sizeof(struct Task));
		task->task_name = (char*)malloc(task_name_len);
		task->pid = pid;
		strcpy(task->task_name, task_name);
		return insert_task(map, task);
	}
	return task;
};

void print_tracenode(struct TreeNode* tnode) {
	struct TraceNode *tracenode = get_node_data(tnode, struct TraceNode, node);
	printf("    Callsite '%s'\n", tracenode->callsite);
}

void print_task_tracenode(struct TreeNode* tnode) {
	struct TraceNode *tracenode = get_node_data(tnode, struct TraceNode, node);
	printf("  Callsite: '%s'\n", tracenode->callsite);
	printf("  Total alloc: '%d', Total req :'%d'\n", tracenode->record.bytes_alloc, tracenode->record.bytes_req);
	iter_tree_node(&tracenode->tracepoints->node, print_tracenode);
}

void print_task(struct Task* task) {
	printf("Task: '%s', Pid :'%d'\n", task->task_name, task->pid);
	printf("Total alloc: '%d', Total req :'%d'\n", task->record.bytes_alloc, task->record.bytes_req);
	iter_tree_node(&task->tracepoints->node, print_task_tracenode);
}

void print_all_tasks(struct HashMap *map) {
	for (int i = 0; i < HASH_BUCKET; i++) {
		if (map->buckets[i] != NULL) {
			print_task
				(get_node_data
				 (map->buckets[i],
				  struct Task,
				  node)
				);
		}
	}
}
