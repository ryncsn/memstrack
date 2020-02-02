#define _GNU_SOURCE
#include <linux/limits.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "memstrack.h"
#include "tracing.h"
#include "proc.h"

#define TASK_NAME_LEN_MAX 1024
#define PID_LEN_MAX 6

unsigned long page_alloc_counter, page_free_counter;

static char *pid_map[65535];
static int total_task_num;
static unsigned long max_pfn;
static unsigned int trivial_peak_limit = 8;

static int comp_task(const void *lht, const void *rht) {
	int diff = ((struct Task*)lht)->pid - ((struct Task*)rht)->pid;
	if (!diff)
		diff = strncmp(((struct Task*)lht)->task_name, ((struct Task*)rht)->task_name, TASK_NAME_LEN_MAX);
	return diff;
}

static int hash_task(const void *task) {
	int hash = ((unsigned int)((struct Task*)task)->pid);

	// for (int i = 0; i < (int)strlen(((struct Task*)task)->task_name); ++i) {
	// 	hash = hash * 31 + ((struct Task*)task)->task_name[i];
	// }

	return hash;
}

struct HashMap TaskMap = {
	hash_task,
	comp_task,
	{NULL},
};

struct PageRecord *page_map;

static struct symbol {
	unsigned long addr;
	char type;
	char* module_name;
	char* sym_name;
} *symbol_table;

int symbol_table_len;

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
	// unsigned long total_pages;
	struct zone_info *zone;

	// total_pages = sysconf(_SC_PHYS_PAGES);
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

static int compTracenode(struct TreeNode *src, struct TreeNode *root) {
	struct Tracenode *src_data = container_of(src, struct Tracenode, node);
	struct Tracenode *root_data = container_of(root, struct Tracenode, node);
	// TODO: Fix if symbol only available on one node
	return (long)src_data->addr - (long)root_data->addr;
}

static int is_trivial_record(struct Record *record) {
	if (!record)
		return 1;

	if (record->pages_alloc == 0 && record->pages_alloc_peak < trivial_peak_limit) {
		return 1;
	}

	return 0;
}

static int is_trivial_tracenode(struct Tracenode *node) {
	if (node->children)
		return 0;

	if (is_trivial_record(node->record)) {
		return 1;
	}

	return 0;
}

/*
 * Try to free a tracenode, if it have no child and have no memory info, then free it
 */
static void free_tracenode(struct Tracenode* tracenode) {
	struct Tracenode *parent;
	while (tracenode) {
		parent = tracenode->parent;

		if (!parent) {
			// It's a task
			return;
		}

		if (tracenode->children) {
			if (tracenode->record)
				free(tracenode->record);
		} else {
			struct TreeNode *tree_root = &parent->children->node;
			get_remove_tree_node(&tree_root, &tracenode->node, compTracenode);

			if (tree_root) {
				parent->children = container_of(tree_root, struct Tracenode, node);
			} else {
				parent->children = NULL;
			}
			free(tracenode);
		}

		tracenode = parent;
	}
}

/*
 * Record that a memory region is being allocated by a tracenode
 * Should only be called against top of the stack
 */
static void record_page_alloc(struct Tracenode *root, unsigned long pfn, unsigned long nr_pages) {
	struct Record *record;
	page_alloc_counter += nr_pages;

	record = root->record;
	record->pages_alloc += nr_pages;
	if (record->pages_alloc > record->pages_alloc_peak) {
		record->pages_alloc_peak = record->pages_alloc;
	}

	// TODO: On older kernel the page struct address is used, need a way to convert to pfn
	if (pfn > max_pfn) {
		pfn = pfn / 4;
		pfn = pfn % max_pfn;
	}

	while (nr_pages--) {
		page_map[pfn++].tracenode = root;
	}
}

/*
 * Record that pages is being freed by a tracenode
 * Should only be called against top of the stack
 */
static void record_page_free(unsigned long pfn, unsigned long nr_pages) {
	struct Tracenode *tracenode = NULL;

	// TODO: On older kernel the page struct address is used, need a way to convert to pfn
	if (pfn > max_pfn) {
		pfn = pfn / 4;
		pfn = pfn % max_pfn;
	}

	while (nr_pages--) {
		if (tracenode != page_map[pfn].tracenode) {
			if (tracenode && is_trivial_tracenode(tracenode)) {
				free_tracenode(tracenode);
				tracenode = NULL;
			}

			if (page_map[pfn].tracenode) {
				tracenode = page_map[pfn].tracenode;
			}
		}

		if (tracenode) {
			tracenode->record->pages_alloc--;
			page_free_counter++;
		}

		page_map[pfn++].tracenode = NULL;
	}

	if (tracenode && is_trivial_tracenode(tracenode)) {
		free_tracenode(tracenode);
		tracenode = NULL;
	}
}

static void do_update_record(struct Tracenode *tracenode, struct PageEvent *pevent) {
	if (pevent->pages_alloc > 0) {
		record_page_alloc(tracenode, pevent->pfn, pevent->pages_alloc);
	} else if (pevent->pages_alloc < 0) {
		record_page_free(pevent->pfn, 0 - pevent->pages_alloc);
	} else {
		log_debug("BUG: Empty Event\n");
	}
}

void update_record(struct Tracenode *tracenode, struct PageEvent *pevent) {
	if (tracenode && !tracenode->record) {
		tracenode->record = calloc(1, sizeof(struct Record));
	}

	do_update_record(tracenode, pevent);
}

void try_update_record(struct Tracenode *tracenode, struct PageEvent *pevent) {
	if (tracenode && tracenode->record)
		do_update_record(tracenode, pevent);
}


struct Tracenode* get_child_tracenode(struct Tracenode *tnode, char *symbol, unsigned long addr) {
	if (tnode->children == NULL) {
		return NULL;
	}

	struct TreeNode *tree_node = &tnode->children->node, *ret_node = NULL;
	struct Tracenode cs_key;

	cs_key.symbol = symbol;
	cs_key.addr = addr;

	ret_node = get_tree_node(&tree_node, &cs_key.node, compTracenode);
	tnode->children = container_of(tree_node, struct Tracenode, node);
	if (ret_node) {
		return container_of(ret_node, struct Tracenode, node);
	} else {
		return NULL;
	}
}

struct Tracenode* insert_child_tracenode(struct Tracenode *tnode, struct Tracenode *src){
	if (tnode->children == NULL) {
		tnode->children = src;
		return src;
	}

	struct TreeNode *tree_node = &tnode->children->node;
	insert_tree_node(&tree_node, &src->node, compTracenode);
	tnode->children = container_of(tree_node, struct Tracenode, node);
	return src;
}

struct Tracenode* get_or_new_child_tracenode(struct Tracenode *root, char *symbol, unsigned long addr){
	struct Tracenode *tracenode;
	tracenode = get_child_tracenode(root, symbol, addr);

	if (tracenode == NULL) {
		tracenode = (struct Tracenode*)calloc(1, sizeof(struct Tracenode));
		if (symbol) {
			int sym_len = strlen(symbol) + 1;
			tracenode->symbol = (char*)malloc(sym_len);
			strcpy(tracenode->symbol, symbol);
		}
		tracenode->addr = addr;
		tracenode->parent = root;
		insert_child_tracenode(root, tracenode);
	}

	return tracenode;
}

static struct Task* try_get_task(char* task_name, int pid) {
	struct Task task_key;
	struct HashNode *hnode;

	task_key.pid = pid;
	task_key.task_name = task_name;
	hnode = get_hash_node(&TaskMap, &task_key);

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
	struct Task *task = try_get_task(task_name, pid);
	if (task == NULL) {
		int task_name_len = strlen(task_name) + 1;
		task = (struct Task*)calloc(1, sizeof(struct Task));
		task->task_name = (char*)malloc(task_name_len);
		task->pid = pid;
		strcpy(task->task_name, task_name);
		total_task_num++;
		return insert_task(map, task);
	}
	return task;
};

struct json_marker {
	int indent;
	int count;
};

static int comp_symbol(const void *x, const void *y) {
	struct symbol *sa = (struct symbol*)x;
	struct symbol *sb = (struct symbol*)y;

	return (sa->addr - sb->addr);
}

void load_kallsyms() {
	struct symbol_buf {
		struct symbol symbol;
		struct symbol_buf *next;
	} *symbol_buf_head, **sym_buf_tail_p, *symbol_buf_tmp;

	sym_buf_tail_p = &symbol_buf_head;
	symbol_table_len = 0;
	if (symbol_table)
		free(symbol_table);

	FILE *proc_kallsyms = fopen("/proc/kallsyms", "r");
	char read_buf[4096];

	while(fgets(read_buf, 4096, proc_kallsyms)) {
		char *addr_arg = strtok(read_buf, " ");
		char *type_arg = strtok(NULL, " ");
		char *symbol_arg = strtok(NULL, " ");
		char *module_arg = strtok(NULL, " ");

		struct symbol_buf *symbol = malloc(sizeof(struct symbol_buf));
		if (module_arg) {
			module_arg[strlen(module_arg) - 1] = '\0';
			while (module_arg[0] == ' ') {
				module_arg++;
			}
			symbol->symbol.module_name = malloc(strlen(module_arg) + 1);
			strcpy(symbol->symbol.module_name, module_arg);
		} else {
			symbol_arg[strlen(symbol_arg) - 1] = '\0';
			symbol->symbol.module_name = NULL;
		}

		symbol->symbol.type = *type_arg;
		sscanf(addr_arg, "%lx", &symbol->symbol.addr);
		symbol->symbol.sym_name = malloc(strlen(symbol_arg) + 1);
		strcpy(symbol->symbol.sym_name, symbol_arg);
		*sym_buf_tail_p = symbol;
		sym_buf_tail_p = &symbol->next;

		symbol_table_len ++;
	}

	symbol_table = malloc(sizeof(struct symbol) * symbol_table_len);
	for (int i = 0; i < symbol_table_len; ++i) {
		symbol_table[i].addr = symbol_buf_head->symbol.addr;
		symbol_table[i].module_name = symbol_buf_head->symbol.module_name;
		symbol_table[i].sym_name = symbol_buf_head->symbol.sym_name;
		symbol_table[i].type = symbol_buf_head->symbol.type;
		symbol_buf_tmp = symbol_buf_head->next;
		free(symbol_buf_head);
		symbol_buf_head = symbol_buf_tmp;
	}

	qsort((void*)symbol_table, symbol_table_len, sizeof(struct symbol), comp_symbol);
}

char* kaddr_to_sym(unsigned long long addr) {
	static char str_buffer[4096];
	int left = 0, right = symbol_table_len, mid;
	do {
		mid = (left + right) / 2;
		if (mid == left || mid == right) {
			mid = left;
			break;
		}

		if (symbol_table[mid].addr > addr) {
			right = mid;
		} else if (symbol_table[mid].addr < addr) {
			left = mid;
		} else {
			break;
		}
	} while (1);

	sprintf(str_buffer, "%s %s (0x%llx)", symbol_table[mid].sym_name, symbol_table[mid].module_name, addr);
	return str_buffer;
};


static void iter_tracenodes(
		struct Tracenode* root,
		void (*op)(struct Tracenode *node, void *blob),
		void *blob)
{
	op(root, blob);

	if (have_left_child(root, node)) {
		iter_tracenodes(left_child(root, struct Tracenode, node),
				op, blob);
	}
	if (have_right_child(root, node)) {
		iter_tracenodes(right_child(root, struct Tracenode, node),
				op, blob);
	}
}

static void depopulate_tracenode(struct Tracenode* tracenode, void *blob) {
	if(tracenode->record) {
		if(tracenode->record->blob)
			free(tracenode->record);
		free(tracenode->record);
	}

	if (tracenode->children)
		iter_tracenodes(tracenode->children, depopulate_tracenode, NULL);
}

/*
 * Allocation info is only recorded at the tracenode represents the top of stack
 * for better performacne, need to collect the info before generate report
 */
static void do_populate_tracenode(struct Tracenode* tracenode, void *blob) {
	struct Record *parent_record = (struct Record*)blob;

	if (tracenode->record == NULL) {
		tracenode->record = calloc(1, sizeof(struct Record));

		if (tracenode->children)
			iter_tracenodes(tracenode->children, do_populate_tracenode, tracenode->record);
	}

	parent_record->pages_alloc += tracenode->record->pages_alloc;
	parent_record->pages_alloc_peak += tracenode->record->pages_alloc_peak;
}

void populate_tracenode(struct Tracenode* tracenode) {
	if (tracenode->record == NULL) {
		tracenode->record = calloc(1, sizeof(struct Record));
	} else {
		memset(tracenode->record, 0, sizeof(struct Record));
	}

	if (tracenode->children)
		iter_tracenodes(tracenode->children, do_populate_tracenode, tracenode->record);
}

static void collect_child_info(struct Tracenode* tracenode, void *blob) {
	struct Record *root_record = (struct Record*)blob;

	if (tracenode->record) {
		root_record->pages_alloc += tracenode->record->pages_alloc;
		root_record->pages_alloc_peak += tracenode->record->pages_alloc_peak;
	} else if (tracenode->children) {
		iter_tracenodes(tracenode->children, collect_child_info, blob);
	} else {
		log_debug("BUG: Empty Tracenode\n");
	}
}

void populate_tracenode_shallow(struct Tracenode* tracenode) {
	if (tracenode->record == NULL) {
		tracenode->record = calloc(1, sizeof(struct Record));
	} else {
		return;
	}

	if (tracenode->children)
		iter_tracenodes(tracenode->children, collect_child_info, tracenode->record);
}

static int comp_tracenode_mem(const void *x, const void *y) {
	long long x_mem, y_mem;

	struct Tracenode *x_n = container_of(*(struct TreeNode**)x, struct Tracenode, node);
	struct Tracenode *y_n = container_of(*(struct TreeNode**)y, struct Tracenode, node);

	x_mem = x_n->record->pages_alloc * page_size;
	y_mem = y_n->record->pages_alloc * page_size;

	if (x_mem == y_mem) {
		return 0;
	} else {
		return (y_mem - x_mem) > 0 ? 1 : -1;
	}
}

static void tracenode_iter_count(struct Tracenode* _, void *blob) {
	int *count = (int*)blob;
	*count += 1;
}

static int count_tracenodes(struct Tracenode *root) {
	int count = 0;
	iter_tracenodes(root, tracenode_iter_count, &count);
	return count;
}

static void tracenode_iter_collect(struct Tracenode* node, void *blob) {
	struct Tracenode ***tail = (struct Tracenode***) blob;
	**tail = node;
	(*tail)++;
}

struct Tracenode **collect_tracenodes_sorted(struct Tracenode *root, int *count, int shallow) {
	struct Tracenode **nodes, **tail;

	*count = count_tracenodes(root);
	tail = nodes = malloc(*count * sizeof(struct Tracenode*));
	iter_tracenodes(root, tracenode_iter_collect, &tail);

	for (int i = 0; i < *count; ++i) {
		if (shallow)
			populate_tracenode_shallow(nodes[i]);
		else
			populate_tracenode(nodes[i]);
	}

	qsort((void*)nodes, *count, sizeof(struct TreeNode*), comp_tracenode_mem);

	return nodes;
}

static int comp_task_mem(const void *x, const void *y) {
	long long x_mem, y_mem;

	struct Task *x_t = *(struct Task**)x;
	struct Task *y_t = *(struct Task**)y;

	x_mem = x_t->tracenode.record->pages_alloc * page_size;
	y_mem = y_t->tracenode.record->pages_alloc * page_size;

	if (x_mem == y_mem) {
		return 0;
	} else {
		return (y_mem - x_mem) > 0 ? 1 : -1;
	}
}

struct Task **collect_tasks_sorted(struct HashMap *map, int *count, int shallow) {
	struct HashNode *hnode = NULL;
	struct Task **tasks;
	int i = 0;

	if (count)
		*count = total_task_num;

	tasks = malloc(total_task_num * sizeof(struct Task*));
	for_each_hnode(map, hnode) {
		tasks[i] = container_of(hnode, struct Task, node);

		if (shallow)
			populate_tracenode_shallow(to_tracenode(tasks[i]));
		else
			populate_tracenode(to_tracenode(tasks[i]));

		i++;
	}

	qsort((void*)tasks, total_task_num, sizeof(struct Task*), comp_task_mem);

	return tasks;
}

static void print_tracenode_json(struct Tracenode* tracenode, void *blob) {
	struct json_marker *current = (struct json_marker*)blob;
	struct json_marker next = {current->indent + 2, 0};
	struct Tracenode **nodes;
	char padding[512] = {0};
	int counter;

	for (int i = 0; i < current->indent + 1; ++i) {
		padding[i] = ' ';
	}
	if (current->count) {
		log_info(",\n");
	}
	if (tracenode->symbol) {
		log_info("%s\"%s\": ", padding, tracenode->symbol);
	} else if (tracenode->addr) {
		log_info("%s\"%s\": ", padding, kaddr_to_sym(tracenode->addr));
	} else {
		log_info("%s\"unknown\": ", padding);
	}
	log_info("{\n");
	log_info("%s \"pages_alloc\": %d", padding, tracenode->record->pages_alloc);
	log_info(",%s \"pages_alloc_peak\": %d", padding, tracenode->record->pages_alloc_peak);
	if (tracenode->children) {
		log_info(",\n%s \"tracenodes\": {\n", padding);
		nodes = collect_tracenodes_sorted(tracenode->children, &counter, 1);
		for (int i = 0; i < counter; i++)
			print_tracenode_json(nodes[i], &next);

		free(nodes);
		log_info("\n%s }\n", padding);
	} else {
		log_info("\n");
	}
	log_info("%s}", padding);
	current->count++;
}

static void print_task_json(struct Task* task, int last_task) {
	struct json_marker marker = {2, 0};
	struct Tracenode **nodes;
	int counter;

	log_info(" {\n");
	log_info("  \"task_name\": \"%s\",\n", task->task_name);
	log_info("  \"pid\" :\"%d\",\n", task->pid);
	log_info("  \"pages_alloc\": %d,\n", task->tracenode.record->pages_alloc);
	log_info("  \"pages_alloc_peak\": %d,\n", task->tracenode.record->pages_alloc_peak);
	log_info("  \"tracenodes\": {\n");
	if(to_tracenode(task)->children) {
		nodes = collect_tracenodes_sorted(to_tracenode(task)->children, &counter, 1);
		for (int i = 0; i < counter; i++)
			print_tracenode_json(nodes[i], &marker);

		free(nodes);
	}
	log_info("\n  }\n");

	if (last_task) {
		log_info(" }\n");
	} else {
		log_info(" },\n");
	}
}

static void print_tracenode(struct Tracenode* tracenode, int current_indent, int substack_limit, int throttle) {
	int next_indent = current_indent + 2, counter, padding = current_indent;
	long page_limit;

	while (padding --)
		log_info(" ");

	if (tracenode->addr) {
		log_info("%s", kaddr_to_sym(tracenode->addr));
	} else {
		log_info("(unknown)");
	}

	log_info(" Pages: %d (peak: %d)\n",
			tracenode->record->pages_alloc,
			tracenode->record->pages_alloc_peak);

	if (m_sort_peak)
		page_limit = tracenode->record->pages_alloc_peak;
	else if (m_sort_alloc)
		page_limit = tracenode->record->pages_alloc;

	if (throttle) {
		page_limit = page_limit * throttle / 100;
	}

	if (tracenode->children) {
		struct Tracenode **nodes;
		nodes = collect_tracenodes_sorted(tracenode->children, &counter, 1);
		for (int i = 0; i < counter &&
				(substack_limit <= 0 || i < substack_limit); i++) {
			print_tracenode(nodes[i], next_indent, substack_limit, throttle);

			if (m_sort_peak)
				page_limit -= nodes[i]->record->pages_alloc_peak;
			else if (m_sort_alloc)
				page_limit -= nodes[i]->record->pages_alloc;
		}
		free(nodes);
	}
}

static void print_task(struct Task* task) {
	int indent, counter;
	struct Tracenode *tn = &task->tracenode;
	struct Tracenode **nodes;

	indent = 2;
	log_info("%s Pages: %d (peak: %d)\n",
			task->task_name,
			tn->record->pages_alloc,
			tn->record->pages_alloc_peak);
	if (to_tracenode(task)->children) {
		nodes = collect_tracenodes_sorted(to_tracenode(task)->children, &counter, 1);
		for (int i = 0; i < counter; i++) {
			print_tracenode(nodes[i], indent, -1, m_throttle);
		}

		free(nodes);
	}
}

static void print_details(struct Task *tasks[], int nr_tasks, long nr_pages_limit)
{
	if (m_json)
		log_info("[\n");
	for (int i = 0; i < nr_tasks && nr_pages_limit > 0; i++) {
		if (m_json) {
			print_task_json(tasks[i], i + 1 == nr_tasks);
		} else {
			print_task(tasks[i]);
		}

		if (m_sort_alloc)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc;
		else if (m_sort_peak)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc_peak;
	}
	if (m_json)
		log_info("]\n");
}

/*
 * Collect top 10 modules, and their top 3 alloc stack
 */
static struct module_usage {
	char *name;
	long pages;
	struct Tracenode *top_node[3];
	struct module_usage *next;
} *module_usages;

static void check_tracenode_for_module(struct Tracenode* tn, void *blob)
{
	char *module_name = strstr(kaddr_to_sym(tn->addr), "[");
	struct module_usage *parent_module = (struct module_usage*)blob;

	if (module_name) {
		struct module_usage **tail = &module_usages;

		if (parent_module) {
			if (strcmp(module_name, parent_module->name) != 0) {
				if (tn->record->pages_alloc > (parent_module->pages * 85 / 100)) {
					tail = &parent_module;
					free((*tail)->name);
					(*tail)->name = strdup(module_name);
				}
			}
		} else {
			while (*tail) {
				if ((*tail)->name != NULL) {
					if (strcmp(module_name, (*tail)->name) == 0) {
						break;
					}
				}
				tail = &(*tail)->next;
			}

			if (!*tail) {
				*tail = calloc(1, sizeof(struct module_usage));
				(*tail)->name = strdup(module_name);
			}

			if (m_sort_alloc)
				(*tail)->pages += tn->record->pages_alloc;
			else if (m_sort_peak)
				(*tail)->pages += tn->record->pages_alloc_peak;
		}

		for (int i = 0; i < 3; ++i) {
			if (!(*tail)->top_node[i]) {
				(*tail)->top_node[i] = tn;
			} else if ((*tail)->top_node[i]->record->pages_alloc < tn->record->pages_alloc) {
				(*tail)->top_node[i] = tn;
				for (int j = i + 1; j < 3; ++j, ++i) {
					(*tail)->top_node[j] = (*tail)->top_node[i];
				}
			}
		}

		if (tn->children) {
			iter_tracenodes(tn->children, check_tracenode_for_module, (*tail));
		}
	} else {
		if (tn->children) {
			iter_tracenodes(tn->children, check_tracenode_for_module, blob);
		}
	}
}

static void print_summary(struct Task *tasks[], int nr_tasks)
{
	int indent = 2;

	for (int i = 0; i < nr_tasks; i++) {
		if (to_tracenode(tasks[i])->children) {
			iter_tracenodes(to_tracenode(tasks[i])->children, check_tracenode_for_module, NULL);
		}
	}

	while (module_usages) {
		log_info("Module %s using %d pages", module_usages->name, module_usages->pages);
		for (int i = 0; i < 3; ++i) {
			if (module_usages->top_node[i])
				print_tracenode(module_usages->top_node[i], indent, 1, m_throttle);
		}
		module_usages = module_usages->next;
	}
}

void final_report(struct HashMap *task_map, int task_limit) {
	long nr_pages_limit;
	struct Task **tasks;

	if (!task_limit) {
		task_limit = total_task_num;
	}

	nr_pages_limit = page_alloc_counter - page_free_counter;
	nr_pages_limit = (nr_pages_limit * m_throttle + 99) / 100;

	tasks = collect_tasks_sorted(task_map, NULL, 0);

	load_kallsyms();

	if (m_summary) {
		print_summary(tasks, task_limit);
	} else {
		print_details(tasks, task_limit, nr_pages_limit);
	}
}
