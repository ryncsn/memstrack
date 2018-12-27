#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "memory-tracer.h"
#include "tracing.h"

#define TASK_NAME_LEN_MAX 1024

struct HashMap TaskMap = {
	hashTask,
	compTask,
	{NULL},
};

char* PidMap[65535];
struct PageRecord *page_bitmap;
struct TreeNode *alloc_record_root;

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
	if (record->bytes_req > record->bytes_req_peak) {
		record->bytes_req_peak = record->bytes_req;
	}
	if (record->bytes_alloc > record->bytes_alloc_peak) {
		record->bytes_alloc_peak = record->bytes_alloc;
	}
	if (record->pages_alloc > record->pages_alloc_peak) {
		record->pages_alloc_peak = record->pages_alloc;
	}
}

static int is_trivial_record(struct Record *record) {
	if (
			record->bytes_req == 0 ||
			record->bytes_alloc == 0 ||
			record->pages_alloc == 0
	   ) {
		return 1;
	}
	return 0;
}

static int compCallsite(struct TreeNode *src, struct TreeNode *root) {
	struct Callsite *src_data = get_node_data(src, struct Callsite, node);
	struct Callsite *root_data = get_node_data(root, struct Callsite, node);
	// TODO: Fix if symbol only available on one node
	return src_data->addr - root_data->addr;
}

struct Callsite* get_child_callsite(struct TraceNode *tnode, char *symbol, unsigned long addr) {
	if (tnode->child_callsites == NULL) {
		return NULL;
	}

	struct TreeNode *tree_node = &tnode->child_callsites->node, *ret_node = NULL;
	struct Callsite tmp;

	tmp.symbol = symbol;
	tmp.addr = addr;

	ret_node = get_tree_node(&tree_node, &tmp.node, compCallsite);

	tnode->child_callsites = get_node_data(tree_node, struct Callsite, node);

	if (ret_node) {
		return get_node_data(ret_node, struct Callsite, node);
	} else {
		return NULL;
	}
}

struct Callsite* insert_child_callsite(struct TraceNode *tnode, struct Callsite *src){
	if (tnode->child_callsites == NULL) {
		tnode->child_callsites = src;
		return src;
	}

	struct TreeNode *tree_node = &tnode->child_callsites->node, *ret_node = NULL;

	ret_node = insert_tree_node(&tree_node, &src->node, compCallsite);

	tnode->child_callsites = get_node_data(tree_node, struct Callsite, node);
	return src;
}

struct Callsite* get_or_new_child_callsite(struct TraceNode *root, char *symbol, unsigned long addr){
	struct Callsite *callsite = get_child_callsite(root, symbol, addr);
	if (callsite == NULL) {
		callsite = (struct Callsite*)calloc(1, sizeof(struct Callsite));
		if (symbol) {
			int sym_len = strlen(symbol) + 1;
			callsite->symbol = (char*)malloc(sym_len);
			strcpy(callsite->symbol, symbol);
		}
		callsite->addr = addr;
		to_tracenode(callsite)->parent = root;
		insert_child_callsite(root, callsite);
	}
	return callsite;
}

void free_callsite(struct TraceNode* tracenode) {
	struct TraceNode *parent = tracenode->parent;
	struct TreeNode *tree_root = &parent->child_callsites->node;
	struct Callsite *callsite = get_node_data(get_remove_tree_node(&tree_root, &to_callsite(tracenode)->node, compCallsite),
			struct Callsite,
			node);
	printf("Freeed %llx!\n", callsite);
	free(callsite);
	if (tree_root == NULL) {
		parent->child_callsites = NULL;
	} else {
		parent->child_callsites = get_node_data(tree_root, struct Callsite, node);
	}
}

static int compAllocRerord(struct TreeNode *src, struct TreeNode *root) {
	struct AllocRecord *src_data = get_node_data(src, struct AllocRecord, node);
	struct AllocRecord *root_data = get_node_data(root, struct AllocRecord, node);
	return src_data->addr - root_data->addr;
}

void record_mem_alloc(struct TraceNode *root, unsigned long addr, unsigned int bytes_req, unsigned int bytes_alloc) {
	struct AllocRecord *rec = calloc(1, sizeof(struct AllocRecord));
	rec->addr = addr;
	rec->bytes_alloc = bytes_alloc;
	rec->bytes_req = bytes_req;
	rec->tracenode = root;
	if (!get_tree_node(&alloc_record_root, &rec->node, compAllocRerord)) {
		insert_tree_node(&alloc_record_root, &rec->node, compAllocRerord);
	}
}

void record_mem_free(unsigned long addr) {
	struct AllocRecord tmp;
	tmp.addr = addr;
	struct TreeNode *record_node = get_remove_tree_node(&alloc_record_root, &tmp.node, compAllocRerord);
	if (!record_node) {
		return;
	}
	struct AllocRecord *rec = get_node_data(
			record_node,
			struct AllocRecord,
			node);
	struct TraceNode *tracenode = rec->tracenode;
	while (tracenode) {
		tracenode->record.bytes_alloc -= rec->bytes_alloc;
		tracenode->record.bytes_req -= rec->bytes_req;
		if (tracenode->parent && is_trivial_record(&tracenode->record)) {
			struct TraceNode *parent = tracenode->parent;
			free_callsite(tracenode);
			tracenode = parent;
		} else {
			tracenode = tracenode->parent;
		}
	}
	free(rec);
}

int compTask(const void *lht, const void *rht) {
	if (((struct Task*)lht)->pid != ((struct Task*)rht)->pid) {
		return ((struct Task*)lht)->pid - ((struct Task*)rht)->pid;
	} else {
		return strncmp(((struct Task*)lht)->task_name, ((struct Task*)rht)->task_name, TASK_NAME_LEN_MAX);
	}
}

int hashTask(const void *task) {
	return 65536 - ((struct Task*)task)->pid;
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
	int *count = (int*)blob;
	*count += 1;
}

void collect_tree_node(struct TreeNode* tnode, void *blob) {
	struct TreeNode ***tail = (struct TreeNode***) blob;
	**tail = tnode;
	(*tail)++;
}

static int comp_callsite_mem(const void *x, const void *y) {
	struct Callsite *x_n = get_node_data(*(struct TreeNode**)x, struct Callsite, node);
	struct Callsite *y_n = get_node_data(*(struct TreeNode**)y, struct Callsite, node);
	unsigned long x_mem, y_mem;
	x_mem = to_tracenode(x_n)->record.pages_alloc * getpagesize();
	x_mem += to_tracenode(x_n)->record.bytes_alloc;
	y_mem = to_tracenode(y_n)->record.pages_alloc * getpagesize();
	y_mem += to_tracenode(y_n)->record.bytes_alloc;
	return x_mem - y_mem;
}

struct TreeNode **collect_sort_callsites(struct TreeNode *root) {
	struct TreeNode **callsites, **tail;
	int count = 0;
	iter_tree_node(root, count_tree_node, &count);
	tail = callsites = calloc(count + 1, sizeof(struct TreeNode*));
	iter_tree_node(root, collect_tree_node, &tail);
	qsort((void*)callsites, count, sizeof(struct TreeNode*), comp_callsite_mem);
	return callsites;
}

void print_callsite(struct TreeNode* tnode, void *blob) {
	struct json_marker *current = (struct json_marker*)blob;
	struct json_marker next = {current->indent + 2, 0};

	char padding[512] = {0};
	struct Callsite *callsite = get_node_data(tnode, struct Callsite, node);
	for (int i = 0; i < current->indent + 1; ++i) {
		padding[i] = ' ';
	}
	if(current->count) {
		log_info(",\n");
	}
	if (callsite->symbol) {
		log_info("%s\"%s\": ", padding, callsite->symbol);
	} else if (callsite->addr) {
		log_info("%s\"%s\": ", padding, _find_symbol(callsite->addr));
	} else {
		log_info("%s\"unknown\": ", padding);
	}
	log_info("{\n");
	log_info("%s \"cache_alloc\": %d,\n", padding, to_tracenode(callsite)->record.bytes_alloc);
	log_info("%s \"cache_req\": %d,\n", padding, to_tracenode(callsite)->record.bytes_req);
	log_info("%s \"pages_alloc\": %d", padding, to_tracenode(callsite)->record.pages_alloc);
	if (to_tracenode(callsite)->child_callsites) {
		log_info(",\n%s \"callsites\": {\n", padding);
		struct TreeNode **nodes;
		nodes = collect_sort_callsites(&to_tracenode(callsite)->child_callsites->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_callsite(nodes[i], &next);
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
	log_info("  \"cache_alloc\": %d,\n", to_tracenode(task)->record.bytes_alloc);
	log_info("  \"cache_req\": %d,\n", to_tracenode(task)->record.bytes_req);
	log_info("  \"pages_alloc\": %d,\n", to_tracenode(task)->record.pages_alloc);
	log_info("  \"callsites\": {\n");
	if(to_tracenode(task)->child_callsites) {
		struct TreeNode **nodes;
		nodes = collect_sort_callsites(&to_tracenode(task)->child_callsites->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_callsite(nodes[i], &marker);
		}
		free(nodes);
	}
	log_info("\n  }\n");
	log_info(" },\n");
}

int comp_task_mem(const void *x, const void *y) {
	struct Task *x_t = *(struct Task**)x;
	struct Task *y_t = *(struct Task**)y;
	unsigned long x_mem, y_mem;
	x_mem = to_tracenode(x_t)->record.pages_alloc * getpagesize();
	x_mem += to_tracenode(x_t)->record.bytes_alloc;
	y_mem = to_tracenode(y_t)->record.pages_alloc * getpagesize();
	y_mem += to_tracenode(y_t)->record.bytes_alloc;

	return x_mem - y_mem;
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
