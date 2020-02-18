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
static unsigned long max_pfn;
static unsigned int trivial_peak_limit = 64;

enum key_type {
	KEY_ADDR = 0,
	KEY_SYMBOL,
} key_type;

void store_symbol_instead(void) {
	key_type = KEY_SYMBOL;
}

char* get_tracenode_module(struct Tracenode *node) {
	if (!node->key)
		return NULL;

	if (key_type == KEY_SYMBOL)
		// TODO
		return NULL;
	else
		return kaddr_to_module(node->addr);
}

char* get_tracenode_symbol(struct Tracenode *node) {
	if (!node->key)
		return "(null)";

	if (key_type == KEY_SYMBOL)
		return node->symbol;
	else
		return kaddr_to_sym(node->addr);
}

static unsigned int comp_task(const struct HashNode *hnode, const void *key) {
	const struct Task *lht = container_of(hnode, struct Task, node);
	const struct Task *rht = key;
	int diff = lht->pid - rht->pid;
	if (!diff)
		diff = strcmp(lht->task_name, rht->task_name);
	return diff;
}

static unsigned int hash_task(const void *key) {
	int hash = ((struct Task *)key)->pid;

	// for (int i = 0; i < (int)strlen(((struct Task*)task)->task_name); ++i) {
	// 	hash = hash * 31 + ((struct Task*)task)->task_name[i];
	// }

	return hash;
}

HASH_MAP(hash_task, comp_task, task_map);

struct PageRecord *page_map;

static struct symbol {
	trace_addr_t addr;
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

static int compTracenode(const struct TreeNode *root, const void *key) {
	struct Tracenode *root_data = container_of(root, struct Tracenode, node);
	if (key_type == KEY_SYMBOL) {
		return strcmp(root_data->symbol, key);
	} else {
		return (long long)root_data->addr - (long long)key;
	}
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

static void do_free_tracenode_record (struct Tracenode *tracenode) {
	if (tracenode->record->blob) {
		free(tracenode->record->blob);
		tracenode->record->blob = NULL;
	}

	free(tracenode->record);
	tracenode->record = NULL;
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
			if (tracenode->record) {
				do_free_tracenode_record(tracenode);
			}
		} else {
			struct TreeNode *tree_root = &parent->children->node;
			get_remove_tree_node(&tree_root, tracenode->key, compTracenode);

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
	struct Tracenode *tracenode, *last = NULL;

	// TODO: On older kernel the page struct address is used, need a way to convert to pfn
	if (pfn > max_pfn) {
		pfn = pfn / 4;
		pfn = pfn % max_pfn;
	}

	while (nr_pages--) {
		tracenode = page_map[pfn].tracenode;

		if (last != tracenode) {
			if (last) {
				if (is_trivial_tracenode(last))
					free_tracenode(last);
				last = NULL;
			}
		}

		if (tracenode) {
			last = tracenode;
			while (tracenode && tracenode->record) {
				tracenode->record->pages_alloc--;
				tracenode = tracenode->parent;
			}
			page_free_counter++;
		}

		page_map[pfn++].tracenode = NULL;
	}

	if (last && is_trivial_tracenode(last)) {
		free_tracenode(last);
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


struct Tracenode* get_child_tracenode(struct Tracenode *tnode, void *key) {
	if (tnode->children == NULL) {
		return NULL;
	}

	struct TreeNode *tree_node = &tnode->children->node, *ret_node = NULL;

	ret_node = get_tree_node(&tree_node, key, compTracenode);
	tnode->children = container_of(tree_node, struct Tracenode, node);
	if (ret_node) {
		return container_of(ret_node, struct Tracenode, node);
	} else {
		return NULL;
	}
}

static void insert_child_tracenode(struct Tracenode *tnode, struct Tracenode *src){
	if (tnode->children == NULL) {
		tnode->children = src;
		return;
	}

	struct TreeNode *tree_node = &tnode->children->node;
	insert_tree_node(&tree_node, &src->node, src->key, compTracenode);
	tnode->children = container_of(tree_node, struct Tracenode, node);
	return;
}

struct Tracenode* get_or_new_child_tracenode(struct Tracenode *root, void *key){
	struct Tracenode *tracenode;
	tracenode = get_child_tracenode(root, key);

	if (tracenode == NULL) {
		tracenode = (struct Tracenode*)calloc(1, sizeof(struct Tracenode));
		tracenode->key = key;
		tracenode->parent = root;
		insert_child_tracenode(root, tracenode);
	}

	return tracenode;
}

static struct Task* try_get_task(char* task_name, long pid) {
	struct Task task_key;
	struct HashNode *hnode;

	task_key.pid = pid;
	task_key.task_name = task_name;
	hnode = get_hash_node(&task_map, &task_key);

	if (hnode) {
		return container_of(
				hnode,
				struct Task,
				node);
	} else {
		return NULL;
	}
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
		insert_hash_node(map, &task->node, task);
		return task;
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
	if (symbol_table) {
		free(symbol_table);
		symbol_table = NULL;
	}

	FILE *proc_kallsyms = fopen("/proc/kallsyms", "r");
	char read_buf[4096];

	while(fgets(read_buf, 4096, proc_kallsyms)) {
		unsigned long long addr;
		char *addr_arg = strtok(read_buf, " \t");
		char *type_arg = strtok(NULL, " \t");
		char *symbol_arg = strtok(NULL, " \t");
		char *module_arg = strtok(NULL, " \t");

		struct symbol_buf *symbol = malloc(sizeof(struct symbol_buf));
		if (module_arg) {
			module_arg[strlen(module_arg) - 1] = '\0';
			module_arg[strlen(module_arg) - 2] = '\0';
			module_arg++;
			symbol->symbol.module_name = strdup(module_arg);
		} else {
			symbol_arg[strlen(symbol_arg) - 1] = '\0';
			symbol->symbol.module_name = NULL;
		}

		symbol->symbol.type = *type_arg;
		sscanf(addr_arg, "%llx", &addr);
		symbol->symbol.sym_name = strdup(symbol_arg);
		*sym_buf_tail_p = symbol;
		sym_buf_tail_p = &symbol->next;
		symbol->symbol.addr = (trace_addr_t)addr;

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

static struct symbol* kaddr_to_symbol(trace_addr_t addr) {
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

	return symbol_table + mid;
}

char* kaddr_to_module(trace_addr_t addr) {
	static char *buffer;

	struct symbol *sym = kaddr_to_symbol(addr);

	if (buffer) {
		free(buffer);
		buffer = NULL;
	}

	if (sym && sym->module_name)
		buffer = strdup(sym->module_name);

	return buffer;
};

char* kaddr_to_sym(trace_addr_t addr) {
	static char *buffer;

	struct symbol *sym = kaddr_to_symbol(addr);

	if (buffer) {
		free(buffer);
		buffer = NULL;
	}

	if (sym) {
		if (sym->module_name) {
			buffer = malloc(strlen(sym->sym_name) + strlen(sym->module_name) + 16 + 6 + 1);
			sprintf(buffer, "%s %s (0x%llx)", sym->sym_name, sym->module_name, (unsigned long long)addr);
		} else {
			buffer = malloc(strlen(sym->sym_name) + 16 + 6 + 1);
			sprintf(buffer, "%s (0x%llx)", sym->sym_name, (unsigned long long)addr);
		}
	}

	return buffer;
};

int for_each_tracenode_ret(
		struct Tracenode* root,
		int (*op)(struct Tracenode *node, void *blob),
		void *blob)
{
	int ret;
	ret = op(root, blob);
	if (ret < 0)
		return ret;

	if (have_left_child(root, node)) {
		ret = for_each_tracenode_ret(left_child(root, struct Tracenode, node),
				op, blob);
	}

	if (ret < 0)
		return ret;

	if (have_right_child(root, node)) {
		ret = for_each_tracenode_ret(right_child(root, struct Tracenode, node),
				op, blob);
	}

	return ret;
}

void for_each_tracenode(
		struct Tracenode* root,
		void (*op)(struct Tracenode *node, void *blob),
		void *blob)
{
	op(root, blob);

	if (have_left_child(root, node)) {
		for_each_tracenode(left_child(root, struct Tracenode, node), op, blob);
	}
	if (have_right_child(root, node)) {
		for_each_tracenode(right_child(root, struct Tracenode, node), op, blob);
	}
}

void do_depopulate_tracenode(struct Tracenode* tracenode, void *blob) {
	if (tracenode->record && tracenode->children) {
		do_free_tracenode_record(tracenode);
		for_each_tracenode(tracenode->children, do_depopulate_tracenode, NULL);
	}
}

void depopulate_tracenode(struct Tracenode* tracenode) {
	do_depopulate_tracenode(tracenode, NULL);
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
			for_each_tracenode(tracenode->children, do_populate_tracenode, tracenode->record);
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
		for_each_tracenode(tracenode->children, do_populate_tracenode, tracenode->record);
}

static void collect_child_info(struct Tracenode* tracenode, void *blob) {
	struct Record *root_record = (struct Record*)blob;

	if (tracenode->record) {
		root_record->pages_alloc += tracenode->record->pages_alloc;
		root_record->pages_alloc_peak += tracenode->record->pages_alloc_peak;
	} else if (tracenode->children) {
		for_each_tracenode(tracenode->children, collect_child_info, blob);
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
		for_each_tracenode(tracenode->children, collect_child_info, tracenode->record);
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
	for_each_tracenode(root, tracenode_iter_count, &count);
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
	for_each_tracenode(root, tracenode_iter_collect, &tail);

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

struct Task **collect_tasks_sorted(struct HashMap *map, int shallow) {
	struct HashNode *hnode = NULL;
	struct Task **tasks;
	int i = 0;

	tasks = malloc(task_map.size * sizeof(struct Task*));
	for_each_hnode(map, hnode) {
		tasks[i] = container_of(hnode, struct Task, node);

		if (shallow)
			populate_tracenode_shallow(to_tracenode(tasks[i]));
		else
			populate_tracenode(to_tracenode(tasks[i]));

		i++;
	}

	qsort((void*)tasks, task_map.size, sizeof(struct Task*), comp_task_mem);

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
	log_info("%s\"%s\": ", padding, get_tracenode_symbol(tracenode));
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

	log_info("%s", get_tracenode_symbol(tracenode));

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
 * Collect stack by modules
 */
int module_count;

struct Module {
	struct HashNode node;
	char *name;
	unsigned int pages;
	struct Tracenode root;
};

static unsigned int comp_module(const struct HashNode *hnode, const void *key) {
	struct Module *mod = container_of(hnode, struct Module, node);
	return strcmp(mod->name, key);
}

static unsigned int hash_module(const void *key) {
	const char *name = key;
	int hash = 42;

	for (int i = 0; i < (int)strlen(name); ++i) {
		hash = hash * 31 + name[i];
	}

	return hash;
}

HASH_MAP(hash_module, comp_module, module_map);

static struct Module *get_or_new_module(char *name)
{
	struct Module *module;
	struct HashNode *hnode;
	hnode = get_hash_node(&module_map, name);
	if (!hnode) {
		module = calloc(1, sizeof(struct Module));
		module->name = strdup(name);
		module->root.record = calloc(1, sizeof(struct Record));
		insert_hash_node(&module_map, &module->node, name);
	} else {
		module = container_of(hnode, struct Module, node);
	}
	return module;
}

static struct Tracenode *merge_into_module(struct Tracenode *node, struct Module *module) {
	struct Tracenode *pnode;

	if (node->parent) {
		pnode = merge_into_module(node->parent, module);
	} else {
		pnode = &module->root;
	}

	pnode = get_or_new_child_tracenode(pnode, node->key);

	// TODO: User a helper to alloc Record
	if (node->record) {
		if (!pnode->record)
			pnode->record = calloc(1, sizeof(struct Record));

		pnode->record->pages_alloc += node->record->pages_alloc;
	}

	return pnode;
}

/* Return number of modules touched */
static void do_gather_tracenodes_by_module(struct Tracenode *node, void *blob)
{
	char *module_name = get_tracenode_module(node);
	struct Module *module = (struct Module *)blob;

	if (module_name) {
		module = get_or_new_module(module_name);
	}

	if (node->children) {
		for_each_tracenode(node->children, do_gather_tracenodes_by_module, module);
	} else if (module) {
		merge_into_module(node, module);
	}
}

static int comp_module_mem(const void *x, const void *y) {
	long long x_mem, y_mem;

	struct Module *x_t = *(struct Module**)x;
	struct Module *y_t = *(struct Module**)y;

	x_mem = x_t->root.record->pages_alloc * page_size;
	y_mem = y_t->root.record->pages_alloc * page_size;

	if (x_mem == y_mem) {
		return 0;
	} else {
		return (y_mem - x_mem) > 0 ? 1 : -1;
	}
}

struct Module **collect_modules_sorted() {
	struct Task *task;
	struct HashNode *hnode;
	struct Module **modules;
	int i = 0;

	for_each_hnode(&task_map, hnode) {
		task = container_of(hnode, struct Task, node);
		if (to_tracenode(task)->children)
			for_each_tracenode(to_tracenode(task)->children, do_gather_tracenodes_by_module, NULL);
	}

	modules = malloc(module_map.size * sizeof(struct Module*));
	for_each_hnode(&module_map, hnode) {
		modules[i] = container_of(hnode, struct Module, node);
		populate_tracenode(&modules[i]->root);
		i++;
	}

	qsort((void*)modules, module_map.size, sizeof(struct Modules*), comp_module_mem);

	return modules;
}

static void module_summary(struct Module *module) {
	log_info("Module %s using %d pages\n", module->name, module->root.record->pages_alloc);
	log_info("Top stack usage:\n");
	print_tracenode(&module->root, 2, 1, 0);
}

static void print_summary(struct Task *tasks[], int nr_tasks)
{
	struct Module **modules;

	modules = collect_modules_sorted();
	for (int i = 0; i < module_map.size; ++i) {
		module_summary(modules[i]);
	}
}

void final_report(struct HashMap *task_map, int task_limit) {
	long nr_pages_limit;
	struct Task **tasks;

	if (!task_limit) {
		task_limit = task_map->size;
	}

	nr_pages_limit = page_alloc_counter - page_free_counter;
	nr_pages_limit = (nr_pages_limit * m_throttle + 99) / 100;

	tasks = collect_tasks_sorted(task_map, 0);

	load_kallsyms();

	if (m_summary) {
		print_summary(tasks, task_limit);
	} else {
		print_details(tasks, task_limit, nr_pages_limit);
	}
}
