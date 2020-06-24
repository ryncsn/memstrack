/*
 * tracing.c
 *
 * Copyright (C) 2020 Red Hat, Inc., Kairui Song <kasong@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "memstrack.h"
#include "tracing.h"
#include "proc.h"

#define PID_LEN_MAX 6

unsigned long page_alloc_counter, page_free_counter;

static unsigned long max_pfn, start_pfn;
static unsigned int trivial_peak_limit = 64;

static unsigned int page_free_always_backtrack;
enum key_type {
	KEY_ADDR = 0,
	KEY_SYMBOL,
} key_type;

// Used for ftrace, kernel will resolve the symbol
void store_symbol_instead(void) {
	key_type = KEY_SYMBOL;
}

// Used for UI, need to update the whole stack trace tree on page free
void need_page_free_always_backtrack(void) {
	page_free_always_backtrack = 1;
}

struct Symbol {
	trace_addr_t addr;
	char type;
	char* module_name;
	char* sym_name;
};

static struct Symbol *symbol_table;
int symbol_table_len;

static struct Symbol* kaddr_to_symbol(trace_addr_t addr) {
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

static char* kaddr_to_module(trace_addr_t addr) {
	static char *buffer;

	struct Symbol *sym = kaddr_to_symbol(addr);

	if (buffer) {
		free(buffer);
		buffer = NULL;
	}

	if (sym && sym->module_name)
		buffer = strdup(sym->module_name);

	return buffer;
};

static char* kaddr_to_sym(trace_addr_t addr) {
	static char *buffer;

	struct Symbol *sym = kaddr_to_symbol(addr);

	if (buffer) {
		free(buffer);
		buffer = NULL;
	}

	if (sym) {
		int buflen;

		if (sym->module_name) {
			buflen = strlen(sym->sym_name) + strlen(sym->module_name) + 16 + 6 + 1;
			buffer = malloc(buflen);
			snprintf(buffer, buflen, "%s %s (0x%llx)", sym->sym_name, sym->module_name, (unsigned long long)addr);
		} else {
			buflen = strlen(sym->sym_name) + 16 + 6 + 1;
			buffer = malloc(buflen);
			snprintf(buffer, buflen, "%s (0x%llx)", sym->sym_name, (unsigned long long)addr);
		}
	}

	return buffer;
};

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
	if (!diff && rht->task_name && lht->task_name)
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

static char* get_process_name_by_pid(const int pid)
{
	char fname_pid_buf[sizeof("/proc//cmdline") + 20 + 1];
	char *buf = NULL;
	FILE *f;

	snprintf(fname_pid_buf, sizeof(fname_pid_buf), "/proc/%d/cmdline", pid);
	f = fopen(fname_pid_buf,"r");
	if (f) {
		size_t len;
		ssize_t read;
		read = getline(&buf, &len, f);
		fclose(f);

		if (read > 0){
			return buf;
		}
	}

	if (buf) {
		free(buf);
		buf = NULL;
	}

	log_debug("Failed to retrive process name of %d\n", pid);
	sprintf(fname_pid_buf, "(%d)", pid);

	return strdup(fname_pid_buf);
}

void mem_tracing_init() {
	// unsigned long total_pages;
	struct zone_info *zone, *tmp;

	// total_pages = sysconf(_SC_PHYS_PAGES);
	parse_zone_info(&zone);
	start_pfn = ULONG_MAX;
	max_pfn = 0;

	trivial_peak_limit = 1024 * 1024 / page_size;

	while (zone) {
		if (max_pfn < zone->spanned + zone->start_pfn)
			max_pfn = zone->spanned + zone->start_pfn;

		if (start_pfn > zone->min)
			start_pfn = zone->min;

		tmp = zone;
		zone = zone->next_zone;
		free(tmp);
	}

	log_debug("max_pfn is %lu\n", max_pfn);

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

static int is_droppable_record(struct Record *record) {
	if (record->pages_alloc == 0 && record->pages_alloc_peak < trivial_peak_limit) {
		return 1;
	}

	return 0;
}

static int is_droppable_tracenode(struct Tracenode *node) {
	if (node->children)
		return 0;

	if (node->record)
		return is_droppable_record(node->record);

	return 1;
}

static void free_tracenode_record(struct Tracenode *tracenode) {
	if (tracenode->record->blob) {
		free(tracenode->record->blob);
	}

	free(tracenode->record);
	tracenode->record = NULL;
}

/*
 * Free/update the parents of a tracenode according to need
 */
static void do_record_page_free(struct Tracenode *tracenode, int nr_pages) {
	struct Tracenode *parent;

	while (tracenode) {
		parent = tracenode->parent;

		if (tracenode->record) {
			tracenode->record->pages_alloc -= nr_pages;

			if (is_droppable_record(tracenode->record))
				free_tracenode_record(tracenode);
		} else {
			if (!page_free_always_backtrack)
				break;
		}

		if (is_droppable_tracenode(tracenode) && parent) {
			struct TreeNode *tree_root = &parent->children->node;
			get_remove_tree_node(&tree_root, tracenode->key, compTracenode);

			// TODO: This tree looks ugly
			if (tree_root) {
				parent->children = container_of(tree_root, struct Tracenode, node);
			} else {
				parent->children = NULL;
			}

			free(tracenode);
			tracenode = NULL;
		}

		tracenode = parent;
	}

}

/*
 * Record that a memory region is being allocated by a tracenode
 * Should only be called against top of the stack
 */
static void record_page_alloc(struct Tracenode *root, unsigned long pfn, unsigned long nr_pages) {
	if (pfn > max_pfn) {
		log_error ("BUG: alloc pfn %lu out of max_pfn %lu\n", pfn, max_pfn);
		return;
	}

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
static void record_page_free(unsigned long pfn_start, unsigned long nr_pages) {
	struct Tracenode *tracenode, *last = NULL;
	unsigned long pfn_off;

	if (pfn_start + nr_pages > max_pfn) {
		log_error ("BUG: free pfn %lu out of max_pfn %lu\n", pfn_start, max_pfn);
		return;
	}

	page_free_counter += nr_pages;
	pfn_off = pfn_start;

	while (nr_pages--) {
		tracenode = page_map[pfn_off].tracenode;

		if (last != tracenode) {
			if (last) {
				do_record_page_free(last, pfn_off - pfn_start + 1);
				last = NULL;
			}
			pfn_start = pfn_off;
		}

		if (tracenode)
			last = tracenode;

		page_map[pfn_off].tracenode = NULL;

		pfn_off++;
	}

	if (last)
		do_record_page_free(last, pfn_off - pfn_start);
}

static void do_update_record(struct Tracenode *tracenode, struct PageEvent *pevent) {
	if (pevent->pages_alloc > 0) {
		if (!tracenode) {
			log_debug("BUG: Page alloc event with NULL tracenode\n");
			return;
		}
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

// TODO:
// task_exit to clean up exited task, so memstrack can run for a longer time reliablely

struct Task* get_or_new_task(char* task_name, int pid) {
	struct Task *task;
	task = try_get_task(task_name, pid);

	if (task == NULL) {
		task = (struct Task*)calloc(1, sizeof(struct Task));
		task->pid = pid;

		if (task_name)
			task->task_name = strdup(task_name);
		else
			task->task_name = get_process_name_by_pid(pid);

		insert_hash_node(&task_map, &task->node, task);
		return task;
	}

	return task;
};

struct json_marker {
	int indent;
	int count;
};

static int comp_symbol(const void *x, const void *y) {
	struct Symbol *sa = (struct Symbol*)x;
	struct Symbol *sb = (struct Symbol*)y;

	return (sa->addr - sb->addr);
}

void load_kallsyms() {
	struct Symbol_buf {
		struct Symbol symbol;
		struct Symbol_buf *next;
	} *symbol_buf_head, **sym_buf_tail_p, *symbol_buf_tmp;

	sym_buf_tail_p = &symbol_buf_head;

	if (symbol_table) {
		for (int i = 0; i < symbol_table_len; ++i) {
			if (symbol_table[i].module_name)
				free(symbol_table[i].module_name);
			free(symbol_table[i].sym_name);
		}
		free(symbol_table);

		symbol_table = NULL;
		symbol_table_len = 0;
	}

	FILE *proc_kallsyms = fopen("/proc/kallsyms", "r");
	char read_buf[4096];

	if (!proc_kallsyms) {
		log_error("Failed to open /proc/kallsyms\n");
		return;
	}

	while(fgets(read_buf, 4096, proc_kallsyms)) {
		unsigned long long addr;
		char *addr_arg = strtok(read_buf, " \t");
		char *type_arg = strtok(NULL, " \t");
		char *symbol_arg = strtok(NULL, " \t");
		char *module_arg = strtok(NULL, " \t");

		struct Symbol_buf *symbol = malloc(sizeof(struct Symbol_buf));
		if (module_arg) {
			module_arg[strlen(module_arg) - 1] = '\0';
			module_arg[strlen(module_arg) - 1] = '\0';
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

	fclose(proc_kallsyms);

	symbol_table = malloc(sizeof(struct Symbol) * symbol_table_len);

	for (int i = 0; i < symbol_table_len; ++i) {
		symbol_table[i].addr = symbol_buf_head->symbol.addr;
		symbol_table[i].module_name = symbol_buf_head->symbol.module_name;
		symbol_table[i].sym_name = symbol_buf_head->symbol.sym_name;
		symbol_table[i].type = symbol_buf_head->symbol.type;
		symbol_buf_tmp = symbol_buf_head;
		symbol_buf_head = symbol_buf_head->next;

		free(symbol_buf_tmp);
	}

	qsort((void*)symbol_table, symbol_table_len, sizeof(struct Symbol), comp_symbol);
}

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
		free_tracenode_record(tracenode);
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
	tail = nodes = calloc(*count * sizeof(struct Tracenode*), 1);
	for_each_tracenode(root, tracenode_iter_collect, &tail);

	for (int i = 0; i < *count; ++i) {
		if (!nodes[i]) {
			*count = i;
			break;
		}

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

struct Task **collect_tasks_sorted(int shallow) {
	struct HashNode *hnode = NULL;
	struct Task **tasks;
	int i = 0;

	tasks = malloc(task_map.size * sizeof(struct Task*));
	for_each_hnode(&task_map, hnode) {
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

void print_tracenode_json(struct Tracenode* tracenode, void *blob) {
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
	log_info("%s \"pages_alloc\": %ld", padding, tracenode->record->pages_alloc);
	log_info(",\n%s \"pages_alloc_peak\": %ld", padding, tracenode->record->pages_alloc_peak);

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

void print_task_json(struct Task* task) {
	struct json_marker marker = {2, 0};
	struct Tracenode **nodes;
	int counter;

	log_info(" {\n");
	log_info("  \"task_name\": \"%s\",\n", task->task_name);
	log_info("  \"pid\" :\"%ld\",\n", task->pid);
	log_info("  \"pages_alloc\": %ld,\n", task->tracenode.record->pages_alloc);
	log_info("  \"pages_alloc_peak\": %ld,\n", task->tracenode.record->pages_alloc_peak);
	log_info("  \"tracenodes\": {\n");
	if(to_tracenode(task)->children) {
		nodes = collect_tracenodes_sorted(to_tracenode(task)->children, &counter, 1);
		for (int i = 0; i < counter; i++)
			print_tracenode_json(nodes[i], &marker);

		free(nodes);
	}
	log_info("\n  }\n");
	log_info(" }");
}

void print_tracenode(struct Tracenode* tracenode, int current_indent, int substack_limit, int throttle) {
	int next_indent = current_indent + 2, counter, padding = current_indent;
	long page_limit;

	while (padding --)
		log_info(" ");

	log_info("%s", get_tracenode_symbol(tracenode));

	log_info(" Pages: %ld (peak: %ld)\n",
			tracenode->record->pages_alloc,
			tracenode->record->pages_alloc_peak);

	if (m_sort_peak)
		page_limit = tracenode->record->pages_alloc_peak;
	else
		page_limit = tracenode->record->pages_alloc;

	if (throttle)
		page_limit = page_limit * throttle / 100;

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

void print_task(struct Task* task) {
	int indent, counter;
	struct Tracenode *tn = &task->tracenode;
	struct Tracenode **nodes;

	indent = 2;
	log_info("%s Pages: %ld (peak: %ld)\n",
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

void print_tasks(struct Task *tasks[], int nr_tasks, long nr_pages_limit, short json, short peak)
{
	if (json)
		log_info("[\n");
	for (int i = 0; i < nr_tasks && nr_pages_limit > 0; i++) {
		if (json) {
			print_task_json(tasks[i]);
		} else {
			print_task(tasks[i]);
		}

		if (m_sort_alloc)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc;
		else if (m_sort_peak)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc_peak;
	}
	if (json)
		log_info("]\n");
}

/*
 * Collect stack by modules
 */
int module_count;

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

struct Module *get_or_new_module(char *name)
{
	struct Module *module;
	struct HashNode *hnode;
	hnode = get_hash_node(&module_map, name);
	if (!hnode) {
		module = calloc(1, sizeof(struct Module));
		module->name = strdup(name);
		module->tracenode.record = calloc(1, sizeof(struct Record));
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
		return &module->tracenode;
	}

	return get_or_new_child_tracenode(pnode, node->key);
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
		struct Tracenode *leaf = merge_into_module(node, module);
		if (!leaf->record)
			leaf->record = calloc(1, sizeof(struct Record));
		leaf->record->pages_alloc += node->record->pages_alloc;
		leaf->record->pages_alloc_peak += node->record->pages_alloc_peak;
	}
}

static int comp_module_mem(const void *x, const void *y) {
	long long x_mem, y_mem;

	struct Module *x_t = *(struct Module**)x;
	struct Module *y_t = *(struct Module**)y;

	x_mem = x_t->tracenode.record->pages_alloc * page_size;
	y_mem = y_t->tracenode.record->pages_alloc * page_size;

	if (x_mem == y_mem) {
		return 0;
	} else {
		return (y_mem - x_mem) > 0 ? 1 : -1;
	}
}

// With shallow = 1, only module memory usage during module initializing is counted
struct Module **collect_modules_sorted(int shallow) {
	struct Task *task;
	struct HashNode *hnode;
	struct Module **modules;
	int i = 0;

	if (!shallow) {
		for_each_hnode(&task_map, hnode) {
			task = container_of(hnode, struct Task, node);
			if (to_tracenode(task)->children)
				for_each_tracenode(to_tracenode(task)->children, do_gather_tracenodes_by_module, NULL);
		}
	}

	modules = malloc(module_map.size * sizeof(struct Module*));
	for_each_hnode(&module_map, hnode) {
		modules[i] = container_of(hnode, struct Module, node);
		if (shallow)
			populate_tracenode_shallow(&modules[i]->tracenode);
		else
			populate_tracenode(&modules[i]->tracenode);
		i++;
	}

	qsort((void*)modules, module_map.size, sizeof(struct Modules*), comp_module_mem);

	return modules;
}
