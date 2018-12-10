#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "memory-tracer.h"
#include "tracing.h"

#define TASK_NAME_LEN_MAX 1024

struct HashMap TaskMap = {
	hashTask,
	compTask,
	{NULL},
};

char* PidMap[65535];

static struct Symbol {
	unsigned long long addr;
	char type;
	char* module;
	char* sym_name;
	struct Symbol *next;
} *Symbols;

static char* get_process_name_by_pid(const int pid)
{
	char* name = (char*)calloc(sizeof(char), TASK_NAME_LEN_MAX);
	if (name) {
		sprintf(name, "/proc/%d/cmdline", pid);
		FILE* f = fopen(name,"r");
		if (f) {
			size_t size;
			size = fread(name, sizeof(char), TASK_NAME_LEN_MAX, f);
			if (size > 0){
				if ('\n' == name[size - 1]) {
					name[size - 1] = '\0';
				}
			}
			fclose(f);
		} else {
			log_error("Failed to retrive process name of %d\n", pid);
			sprintf(name, "(%d)", pid);
		}
	} else {
		return NULL;
	}
	return name;
}

void update_record(struct Record *record, struct Event *event) {
	record->bytes_req += event->bytes_req;
	record->bytes_alloc += event->bytes_alloc;
	record->pages_alloc += event->pages_alloc;
}

int compTraceNodeResolved(struct TreeNode *src, struct TreeNode *root) {
	struct TraceNode *src_data = get_node_data(src, struct TraceNode, node);
	struct TraceNode *root_data = get_node_data(root, struct TraceNode, node);
	return strcmp(src_data->callsite, root_data->callsite);
}

int compTraceNodeRaw(struct TreeNode *src, struct TreeNode *root) {
	struct TraceNode *src_data = get_node_data(src, struct TraceNode, node);
	struct TraceNode *root_data = get_node_data(root, struct TraceNode, node);
	return src_data->callsite_addr - root_data->callsite_addr;
}

struct TraceNode* get_tracepoint(struct TraceNode **root, char *callsite){
	if (*root == NULL)
		return NULL;

	struct TreeNode *rnode = &((*root)->node), *tnode = NULL;
	struct TraceNode temp_node;
	temp_node.callsite = callsite;
	tnode = get_tree_node(&rnode, &temp_node.node, compTraceNodeResolved);
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

struct TraceNode* insert_tracepoint(struct TraceNode **root, struct TraceNode *src){
	if (*root == NULL) {
		return *root = src;
	}
	struct TreeNode *rnode = &((*root)->node);
	insert_tree_node(&rnode, &src->node, compTraceNodeResolved);
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
		insert_tracepoint(root, tracepoint);
		return tracepoint;
	} else {
		return tracepoint;
	}
}

struct TraceNode* get_tracepoint_raw(struct TraceNode **root, unsigned long long callsite_addr){
	if (*root == NULL)
		return NULL;

	struct TreeNode *rnode = &((*root)->node), *tnode = NULL;
	struct TraceNode temp_node;
	temp_node.callsite_addr = callsite_addr;
	tnode = get_tree_node(&rnode, &temp_node.node, compTraceNodeRaw);
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

struct TraceNode* insert_tracepoint_raw(struct TraceNode **root, struct TraceNode *src){
	if (*root == NULL) {
		return *root = src;
	}
	struct TreeNode *rnode = &((*root)->node);
	insert_tree_node(&rnode, &src->node, compTraceNodeRaw);
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

struct TraceNode* get_or_new_tracepoint_raw(struct TraceNode **root, unsigned long long callsite_addr){
	struct TraceNode *tracepoint = get_tracepoint_raw(root, callsite_addr);
	if (tracepoint == NULL) {
		tracepoint = (struct TraceNode*)calloc(1, sizeof(struct TraceNode));
		tracepoint->callsite_addr = callsite_addr;
		insert_tracepoint_raw(root, tracepoint);
		return tracepoint;
	} else {
		return tracepoint;
	}
}


int compTask(const void *lht, const void *rht) {
	if (((struct Task*)lht)->pid != ((struct Task*)rht)->pid) {
		return ((struct Task*)lht)->pid - ((struct Task*)rht)->pid;
	} else {
		return strncmp(((struct Task*)lht)->task_name, ((struct Task*)rht)->task_name, TASK_NAME_LEN_MAX);
	}
}

int hashTask(const void *task) {
	return ((struct Task*)task)->pid;
}

struct Task* get_task(struct HashMap *map, char* task_name, int pid) {
	struct Task tmp_task;
	tmp_task.pid = pid;
	tmp_task.task_name = task_name;
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
	if (task_name == NULL) {
		// TODO: Remove Pid map entry if previous task exited
		char *cmdline = PidMap[pid % 65535];
		if (!cmdline) {
			cmdline = PidMap[pid % 65535] = get_process_name_by_pid(pid);
		}
		task_name = cmdline;
	}
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

struct json_marker {
	int indent;
	int count;
};

static void _load_kallsyms() {
	FILE *proc_kallsyms = fopen("/proc/kallsyms", "r");
	char kallsyms_line[4096];
	struct Symbol **sym_tail = &Symbols;
	while(fgets(kallsyms_line, 4096, proc_kallsyms)) {
		char *addr_arg = strtok(kallsyms_line, " ");
		char *type_arg = strtok(NULL, " ");
		char *symbol_arg = strtok(NULL, " ");
		char *module_arg = strtok(NULL, " ");

		struct Symbol *symbol = malloc(sizeof(struct Symbol));
		if (module_arg) {
			module_arg[strlen(module_arg) - 1] = '\0';
			while (module_arg[0] == ' ') {
				module_arg++;
			}
			symbol->module = malloc(strlen(module_arg) + 1);
			strcpy(symbol->module, module_arg);
		} else {
			symbol_arg[strlen(symbol_arg) - 1] = '\0';
			symbol->module = NULL;
		}

		symbol->type = *type_arg;
		sscanf(addr_arg, "%llx", &symbol->addr);
		symbol->sym_name = malloc(strlen(symbol_arg) + 1);
		strcpy(symbol->sym_name, symbol_arg);
		symbol->next = NULL;

		*sym_tail = symbol;
		sym_tail = &symbol->next;
	}
}

static char* _find_symbol(unsigned long long addr) {
	static char _format_buffer[4096];
	struct Symbol *head = Symbols;
	struct Symbol *closest = head;
	while (head != NULL) {
		if (head->addr < addr) {
			if (head->addr - addr > closest->addr - addr) {
				closest = head;
			}
		}
		head = head->next;
	}
	if (closest) {
		sprintf(_format_buffer, "%s %s", closest->sym_name, closest->module);
	} else {
		sprintf(_format_buffer, "0x%llx", addr);
	}
	return _format_buffer;
};

void count_tree_node(struct TreeNode* _, void *blob) {
	int *count = (int*) blob;
	*count += 1;
}

void collect_tree_node(struct TreeNode* tnode, void *blob) {
	struct TreeNode ***tail = (struct TreeNode***) blob;
	**tail = tnode;
	(*tail) ++;
}

static int comp_callsite_node_mem(const void *x, const void *y) {
	struct TraceNode *x_n = get_node_data(*(struct TreeNode**)x, struct TraceNode, node);
	struct TraceNode *y_n = get_node_data(*(struct TreeNode**)y, struct TraceNode, node);
	return x_n->record.pages_alloc < y_n->record.pages_alloc;
}

struct TreeNode **sort_callsites(struct TreeNode *root) {
	int count = 0;
	struct TreeNode **callsites, **tail;
	iter_tree_node(root, count_tree_node, &count);
	tail = callsites = calloc(count + 1, sizeof(struct TreeNode*));
	iter_tree_node(root, collect_tree_node, &tail);
	qsort((void*)callsites, count, sizeof(struct TreeNode*), comp_callsite_node_mem);
	return callsites;
}

void print_tracenode(struct TreeNode* tnode, void *blob) {
	struct json_marker *current = (struct json_marker*)blob;
	struct json_marker next = {current->indent + 2, 0};

	char padding[512] = {0};
	struct TraceNode *tracenode = get_node_data(tnode, struct TraceNode, node);
	for (int i = 0; i < current->indent + 1; ++i) {
		padding[i] = ' ';
	}
	if(current->count) {
		log_info(",\n");
	}
	if (tracenode->callsite) {
		log_info("%s\"%s\": ", padding, tracenode->callsite);
	} else if (tracenode->callsite_addr) {
		log_info("%s\"%s\": ", padding, _find_symbol(tracenode->callsite_addr));
	} else {
		log_info("%s\"unknown\": ", padding);
	}
	log_info("{\n");
	log_info("%s \"cache_alloc\": %d,\n", padding, tracenode->record.bytes_alloc);
	log_info("%s \"cache_req\": %d,\n", padding, tracenode->record.bytes_req);
	log_info("%s \"pages_alloc\": %d", padding, tracenode->record.pages_alloc);
	if (tracenode->tracepoints) {
		log_info(",\n%s \"callsites\": {\n", padding);
		struct TreeNode **nodes;
		nodes = sort_callsites(&tracenode->tracepoints->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_tracenode(nodes[i], &next);
		}
		free(nodes);
		log_info("\n%s }\n", padding);
	} else {
		log_info("\n");
	}
	log_info("%s}", padding);
	current->count++;
}

void print_task(struct Task* task) {
	struct json_marker marker = {2, 0};
	log_info(" {\n");
	log_info("  \"task_name\": \"%s\",\n", task->task_name);
	log_info("  \"pid\" :\"%d\",\n", task->pid);
	log_info("  \"cache_alloc\": %d,\n", task->record.bytes_alloc);
	log_info("  \"cache_req\": %d,\n", task->record.bytes_req);
	log_info("  \"pages_alloc\": %d,\n", task->record.pages_alloc);
	log_info("  \"callsites\": {\n");
	if(task->tracepoints) {
		struct TreeNode **nodes;
		nodes = sort_callsites(&task->tracepoints->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_tracenode(nodes[i], &marker);
		}
		free(nodes);
	}
	log_info("\n  }\n");
	log_info(" },\n");
}

int comp_task_mem(const void *x, const void *y) {
	return (*(struct Task**)x)->record.pages_alloc < (*(struct Task**)y)->record.pages_alloc;
}

struct Task **sort_tasks(struct HashMap *map) {
	struct Task **tasks = NULL;
	struct HashNode *node = NULL;
	int task_count = 0;
	for (int i = 0; i < HASH_BUCKET; i++) {
		if (map->buckets[i] != NULL) {
			node = map->buckets[i];
			while(node) {
				node = node->next;
				task_count ++;
			}
		}
	}
	tasks = calloc(task_count + 1, sizeof(struct Task*));
	task_count = 0;
	for (int i = 0; i < HASH_BUCKET; i++) {
		if (map->buckets[i] != NULL) {
			node = map->buckets[i];
			while(node) {
				tasks[task_count] = (get_node_data
					 (node,
					  struct Task,
					  node)
					);
				task_count ++;
				node = node->next;
			}
		}
	}

	tasks[task_count] = NULL;
	qsort((void*)tasks, task_count, sizeof(struct Task*), comp_task_mem);

	return tasks;
}

void print_all_tasks(struct HashMap *map) {
	_load_kallsyms();
	log_info("[\n");
	struct Task **task = sort_tasks(map);
	for (int i = 0; task[i] != NULL; i++) {
		print_task(task[i]);
	}
	log_info("]\n");
}
