#define _GNU_SOURCE
#include <linux/limits.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "memory-tracer.h"
#include "tracing.h"
#include "proc.h"

#define TASK_NAME_LEN_MAX 1024
#define PID_LEN_MAX 6

unsigned long total_alloc, total_free;

static char *pid_map[65535];
int task_num;

static int comp_task(const void *lht, const void *rht) {
	int diff = ((struct Task*)lht)->pid - ((struct Task*)rht)->pid;
	if (!diff)
		diff = strncmp(((struct Task*)lht)->task_name, ((struct Task*)rht)->task_name, TASK_NAME_LEN_MAX);
	return diff;
}

static int hash_task(const void *task) {
	return ((struct Task*)task)->pid;
}

struct HashMap TaskMap = {
	hash_task,
	comp_task,
	{NULL},
};

struct PageRecord *page_map;

static struct Symbol {
	unsigned long long addr;
	char type;
	char* module;
	char* sym_name;
	struct Symbol *next;
} *Symbols;

static char* get_process_name_by_pid(const int pid)
{
	char fname_buf[sizeof("/proc/65535/cmdline")];
	char *name;
	FILE *f;

	sprintf(fname_buf, "/proc/%d/cmdline", pid);
	f = fopen(fname_buf,"r");
	if (f) {
		size_t size;
		name = (char*)malloc(TASK_NAME_LEN_MAX);
		size = fread(name, sizeof(char), TASK_NAME_LEN_MAX, f);
		if (size > 0){
			name[size - 1] = '\0';
		}
		fclose(f);
	} else {
		log_debug("Failed to retrive process name of %d\n", pid);
		name = (char*)malloc(PID_LEN_MAX + 2);
		sprintf(name, "(%d)", pid);
	}

	return name;
}

void mem_tracing_init() {
	struct zone_info *zone;
	unsigned long total_pages;
	unsigned long max_pfn;

	total_pages = sysconf(_SC_PHYS_PAGES);
	parse_zone_info(&zone);
	max_pfn = 0;

	while (zone) {
		if (max_pfn < zone->spanned + zone->start_pfn)
			max_pfn = zone->spanned + zone->start_pfn;
		zone = zone->next_zone;
	}

	// TODO: handle holes to save memory
	page_map = calloc(max_pfn, sizeof(struct PageRecord));
}

void update_record(struct TraceNode *tracenode, struct PageEvent *pevent, struct AllocEvent *aevent) {
	struct Record *record;

	if (!tracenode->record) {
		tracenode->record = calloc(1, sizeof(struct Record));
	}

	record = tracenode->record;
	record->pages_alloc += pevent->pages_alloc;

	if (record->pages_alloc > record->pages_alloc_peak) {
		record->pages_alloc_peak = record->pages_alloc;
	}
}

static int is_empty_tracenode(struct TraceNode *node) {
	struct Record *record;

	if (node->child_callsites != NULL) {
		return 0;
	}

	record = node->record;
	if (record->count == 0) {
		if (record->pages_alloc != 0) {
			log_error("Freeing node still have memory allocation data ");
			log_error("(addr %lx, pages_alloc:%d)\n", to_callsite(node)->addr, record->pages_alloc);
		}
		return 1;
	}
	return 0;
}

static int compCallsite(struct TreeNode *src, struct TreeNode *root) {
	struct Callsite *src_data = container_of(src, struct Callsite, node);
	struct Callsite *root_data = container_of(root, struct Callsite, node);
	// TODO: Fix if symbol only available on one node
	return (long)src_data->addr - (long)root_data->addr;
}

struct Callsite* get_child_callsite(struct TraceNode *tnode, char *symbol, unsigned long addr) {
	if (tnode->child_callsites == NULL) {
		return NULL;
	}

	struct TreeNode *tree_node = &tnode->child_callsites->node, *ret_node = NULL;
	struct Callsite cs_key;

	cs_key.symbol = symbol;
	cs_key.addr = addr;

	ret_node = get_tree_node(&tree_node, &cs_key.node, compCallsite);
	tnode->child_callsites = container_of(tree_node, struct Callsite, node);
	if (ret_node) {
		return container_of(ret_node, struct Callsite, node);
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
	tnode->child_callsites = container_of(tree_node, struct Callsite, node);
	return src;
}

struct Callsite* get_or_new_child_callsite(struct TraceNode *root, char *symbol, unsigned long addr){
	struct Callsite *callsite;
	callsite = get_child_callsite(root, symbol, addr);

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

static int compAllocRerord(struct TreeNode *src, struct TreeNode *root) {
	struct AllocRecord *src_data = container_of(src, struct AllocRecord, node);
	struct AllocRecord *root_data = container_of(root, struct AllocRecord, node);
	return (long)src_data->addr - (long)root_data->addr;
}

/*
 * Try to free a callsite, if it have no child and have no memory info, then free it
 */
static void free_callsite(struct TraceNode* tracenode) {
	if (tracenode->record->count) {
		// Still have memory allocated
		return;
	}
	while (tracenode) {
		if (tracenode->parent == NULL) {
			// It's a task
			return;
		}
		if (!tracenode->child_callsites) {
			struct TraceNode *parent = tracenode->parent;
			struct TreeNode *tree_root = &parent->child_callsites->node;
			get_remove_tree_node(&tree_root, &to_callsite(tracenode)->node, compCallsite);
			if (tree_root) {
				parent->child_callsites = container_of(tree_root, struct Callsite, node);
			} else {
				parent->child_callsites = NULL;
			}
			free(tracenode);
			tracenode = parent;
		} else {
			free(tracenode->record);
			tracenode->record = NULL;
			return;
		}
	}
}

/*
 * Record that a memory region is being allocated by a tracenode
 * Should only be called against top of the stack
 */
void record_page_alloc(struct TraceNode *root, unsigned long pfn, unsigned long nr_pages) {
	total_alloc += page_size * nr_pages;

	while (nr_pages--) {
		page_map[pfn++].tracenode = root;
	}
}

/*
 * Record that pages is being freed by a tracenode
 * Should only be called against top of the stack
 */
void record_page_free(unsigned long pfn, unsigned long nr_pages) {
	struct TraceNode *tracenode = NULL, *parent;

	while (nr_pages--) {
		total_free += page_size;
		if (page_map[pfn].tracenode != NULL && tracenode != page_map[pfn].tracenode) {
			tracenode = page_map[pfn].tracenode;

			if (is_empty_tracenode(tracenode)) {
				parent = tracenode->parent;
				free_callsite(tracenode);
			}
		}

		page_map[pfn++].tracenode = NULL;
	}
}

static struct Task* try_get_task(struct HashMap *map, char* task_name, int pid) {
	struct Task task_key;
	struct HashNode *hnode;

	task_key.pid = pid;
	task_key.task_name = task_name;
	hnode = get_hash_node(map, &task_key);

	if (hnode) {
		return container_of(
				hnode,
				struct Task,
				node);
	} else {
		return NULL;
	}
};

struct Task* insert_task(struct HashMap *map, struct Task* task) {
	return container_of
		(insert_hash_node(map, &task->node, task),
		 struct Task,
		 node);
};

struct Task* get_or_new_task(struct HashMap *map, char* task_name, int pid) {
	if (task_name == NULL) {
		// TODO: Remove Pid map entry if previous task exited
		char *cmdline = pid_map[pid % 65535];
		if (!cmdline) {
			cmdline = pid_map[pid % 65535] = get_process_name_by_pid(pid);
		}
		task_name = cmdline;
	}
	struct Task *task = try_get_task(map, task_name, pid);
	if (task == NULL) {
		int task_name_len = strlen(task_name) + 1;
		task = (struct Task*)calloc(1, sizeof(struct Task));
		task->task_name = (char*)malloc(task_name_len);
		task->pid = pid;
		strcpy(task->task_name, task_name);
		task_num++;
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
		sprintf(_format_buffer, "%s %s (0x%llx)", closest->sym_name, closest->module, addr);
	} else {
		sprintf(_format_buffer, "0x%llx", addr);
	}
	return _format_buffer;
};

/*
 * Allocation info is only recorded at the tracenode represents the top of stack
 * for better performacne, need to collect the info before generate report
 */
static void collect_child_info(struct TraceNode* tracenode);

static void populate_child_callsites(struct TreeNode* treenode, void *blob) {
	struct Record *parent_record = (struct Record*)blob;
	struct Callsite *callsite = container_of(treenode, struct Callsite, node);

	collect_child_info(to_tracenode(callsite));

	parent_record->pages_alloc += to_tracenode(callsite)->record->pages_alloc;
	parent_record->pages_alloc_peak += to_tracenode(callsite)->record->pages_alloc_peak;
}

static void collect_child_info(struct TraceNode* tracenode) {
	if (tracenode->record == NULL) {
		tracenode->record = calloc(1, sizeof(struct Record));
	} else {
		return;
	}
	if (tracenode->child_callsites) {
		iter_tree_node(&tracenode->child_callsites->node, populate_child_callsites, tracenode->record);
	}
}

void count_tree_node(struct TreeNode* _, void *blob) {
	int *count = (int*)blob;
	*count += 1;
}

void collect_tree_node(struct TreeNode* tnode, void *blob) {
	struct TreeNode ***tail = (struct TreeNode***) blob;
	struct TraceNode *tn = to_tracenode(container_of(tnode, struct Callsite, node));
	collect_child_info(tn);
	**tail = tnode;
	(*tail)++;
}

static int comp_callsite_mem(const void *x, const void *y) {
	long long x_mem, y_mem;

	struct Callsite *x_n = container_of(*(struct TreeNode**)x, struct Callsite, node);
	struct Callsite *y_n = container_of(*(struct TreeNode**)y, struct Callsite, node);

	x_mem = to_tracenode(x_n)->record->pages_alloc * page_size;
	y_mem = to_tracenode(y_n)->record->pages_alloc * page_size;

	if (x_mem == y_mem) {
		return 0;
	} else {
		return (y_mem - x_mem) > 0 ? 1 : -1;
	}
}

static struct TreeNode **collect_sort_callsites(struct TreeNode *root) {
	int count = 0;
	struct TreeNode **callsites, **tail;

	iter_tree_node(root, count_tree_node, &count);
	tail = callsites = malloc((count + 1) * sizeof(struct TreeNode*));

	iter_tree_node(root, collect_tree_node, &tail);
	qsort((void*)callsites, count, sizeof(struct TreeNode*), comp_callsite_mem);

	return callsites;
}

static int comp_task_mem(const void *x, const void *y) {
	long long x_mem, y_mem;

	struct Task *x_t = *(struct Task**)x;
	struct Task *y_t = *(struct Task**)y;

	x_mem = to_tracenode(x_t)->record->pages_alloc * page_size;
	y_mem = to_tracenode(y_t)->record->pages_alloc * page_size;

	if (x_mem == y_mem) {
		return 0;
	} else {
		return (y_mem - x_mem) > 0 ? 1 : -1;
	}
}

static struct Task **sort_tasks(struct HashMap *map) {
	struct Task **tasks = NULL;
	struct HashNode *node = NULL;

	tasks = malloc((task_num + 1) * sizeof(struct Task*));
	tasks[task_num] = NULL;

	for (int i = 0, j = 0; i < HASH_BUCKET; i++) {
		if (map->buckets[i] != NULL) {
			node = map->buckets[i];
			while(node) {
				tasks[j] = container_of(node, struct Task, node);
				collect_child_info(to_tracenode(tasks[j]));
				node = node->next;
				j++;
			}
		}
	}

	qsort((void*)tasks, task_num, sizeof(struct Task*), comp_task_mem);

	return tasks;
}

void print_callsite_json(struct TreeNode* tnode, void *blob) {
	struct json_marker *current = (struct json_marker*)blob;
	struct json_marker next = {current->indent + 2, 0};

	char padding[512] = {0};
	struct Callsite *callsite = container_of(tnode, struct Callsite, node);
	for (int i = 0; i < current->indent + 1; ++i) {
		padding[i] = ' ';
	}
	if (current->count) {
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
	log_info("%s \"pages_alloc\": %d", padding, to_tracenode(callsite)->record->pages_alloc);
	log_info(",%s \"pages_alloc_peak\": %d", padding, to_tracenode(callsite)->record->pages_alloc_peak);
	if (to_tracenode(callsite)->child_callsites) {
		log_info(",\n%s \"callsites\": {\n", padding);
		struct TreeNode **nodes;
		nodes = collect_sort_callsites(&to_tracenode(callsite)->child_callsites->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_callsite_json(nodes[i], &next);
		}
		free(nodes);
		log_info("\n%s }\n", padding);
	} else {
		log_info("\n");
	}
	log_info("%s}", padding);
	current->count++;
}

void print_task_json(struct Task* task, int last_task) {
	struct json_marker marker = {2, 0};
	log_info(" {\n");
	log_info("  \"task_name\": \"%s\",\n", task->task_name);
	log_info("  \"pid\" :\"%d\",\n", task->pid);
	log_info("  \"pages_alloc\": %d,\n", to_tracenode(task)->record->pages_alloc);
	log_info("  \"pages_alloc_peak\": %d,\n", to_tracenode(task)->record->pages_alloc_peak);
	log_info("  \"callsites\": {\n");
	if(to_tracenode(task)->child_callsites) {
		struct TreeNode **nodes;
		nodes = collect_sort_callsites(&to_tracenode(task)->child_callsites->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_callsite_json(nodes[i], &marker);
		}
		free(nodes);
	}
	log_info("\n  }\n");

	if (last_task) {
		log_info(" }\n");
	} else {
		log_info(" },\n");
	}
}

void print_callsite(struct TreeNode* tnode, void *blob) {
	int current_indent = *(int*)blob;
	int next_indent = current_indent + 2;

	char* padding = calloc(current_indent + 1, sizeof(char));
	for (int i = 0; i < current_indent; ++i) {
		padding[i] = ' ';
	}

	struct Callsite *callsite = container_of(tnode, struct Callsite, node);
	struct TraceNode *tracenode = to_tracenode(callsite);

	if (callsite->symbol) {
		log_info("%s%s", padding, callsite->symbol);
	} else if (callsite->addr) {
		log_info("%s%s", padding, _find_symbol(callsite->addr));
	} else {
		log_info("%s(unknown)", padding);
	}

	log_info(" Pages: %d (peak: %d)\n",
			tracenode->record->pages_alloc,
			tracenode->record->pages_alloc_peak);

	if (tracenode->child_callsites) {
		struct TreeNode **nodes;
		nodes = collect_sort_callsites(&to_tracenode(callsite)->child_callsites->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_callsite(nodes[i], &next_indent);
		}
		free(nodes);
	}
}

void print_task(struct Task* task) {
	int indent;
	struct TraceNode *tn = to_tracenode(task);
	log_info("%s Pages: %d (peak: %d)\n",
			task->task_name,
			tn->record->pages_alloc,
			tn->record->pages_alloc_peak);
	if (to_tracenode(task)->child_callsites) {
		struct TreeNode **nodes;
		indent = 2;
		nodes = collect_sort_callsites(&to_tracenode(task)->child_callsites->node);
		for (int i = 0; nodes[i] != NULL; i++) {
			print_callsite(nodes[i], &indent);
		}
		free(nodes);
	}
}

void generate_stack_statistic(struct HashMap *task_map, int task_limit) {
	struct Task **tasks;

	_load_kallsyms();
	tasks = sort_tasks(task_map);

	if (memtrac_json)
		log_info("[\n");
	for (int i = 0; tasks[i] != NULL && i < task_limit; i++) {
		if (memtrac_json) {
			print_task_json(tasks[i], tasks[i + 1] == NULL || i + 1 == task_limit);
		} else {
			print_task(tasks[i]);
		}
	}
	if (memtrac_json)
		log_info("]\n");
}
