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
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>

#include "memstrack.h"
#include "tracing.h"
#include "proc.h"

#define PID_LEN_MAX 6

unsigned int page_size;
unsigned long trace_count;
unsigned long page_alloc_counter, page_free_counter;

static unsigned long max_pfn, start_pfn;
static unsigned int trivial_peak_limit = 64;

static bool page_free_always_backtrack;
/* Used by TUI currently, allow to mark a tracenode extended,
 * so when any event happened to child of the tracenode, the
 * info of the extended tracenode will be updated */
static bool tracenode_extendable;

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

void need_tracenode_extendable(void) {
	tracenode_extendable = 1;
}

bool is_tracenode_extended(struct Tracenode *node) {
	if (!tracenode_extendable)
		return false;

	/* If a tracenode is extended, all of its direct children
	 * have record. Else, none of its child has record.
	 * For the tracenode that have a child which presents a stack top,
	 * it's always extended */
	if (node->children && node->children->record)
		return true;

	return false;
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

static unsigned int comp_task(const struct HashNode *hnode, const void* key) {
	const struct Task *task = container_of(hnode, struct Task, node);
	long pid = *(long*)key;

	return task->pid - pid;
}

static unsigned int hash_task(const void *key) {
	long hash = *(long*)key;

	// for (int i = 0; i < (int)strlen(((struct Task*)task)->task_name); ++i) {
	// 	hash = hash * 31 + ((struct Task*)task)->task_name[i];
	// }

	return hash;
}

static HASH_MAP(hash_task, comp_task, active_task_map);
static HASH_MAP(hash_task, comp_task, exited_task_map);

struct PageRecord *page_map;

static char* get_process_name_by_pid(const int pid)
{

	char fname_buf[sizeof("/proc//cmdline") + 20 + 1];
	char read_buf[1024];
	FILE *f;

	sprintf(fname_buf, "/proc/%d/cmdline", pid);
	f = fopen(fname_buf, "r");
	if (f) {
		ssize_t read;
		read = fread(&read_buf, 1, 1024, f);
		fclose(f);

		if (read > 0) {
			read_buf[read - 1] = '\0';

			for (int i = 0; i < read - 1; ++i) {
				if (read_buf[i] == '\0') {
					read_buf[i] = ' ';
				}
			}

			return strdup(read_buf);
		}
	}

	log_debug("Failed to retrive process name of %d\n", pid);
	sprintf(read_buf, "(%d)", pid);

	return strdup(read_buf);
}

int mem_tracing_init() {
	// unsigned long total_pages;
	struct zone_info *zone, *tmp;

	page_size = getpagesize();

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

	// with MAP_ANONYMOUS and MAP_NORESERVE, it can alloc more virtual memory
	// than actually available memory. So even big memory hole that make the map large that avaiable memory
	// won't be a problem, and kernel should ensure its contents are initialized to zero on read.
	page_map = mmap(NULL, max_pfn * sizeof(struct PageRecord), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE, -1, 0);
	if (page_map == MAP_FAILED) {
		log_error("Failed to create page map\n");
		return -1;
	}

	return 0;
}

static int compTracenode(const struct TreeNode *root, const void *key) {
	struct Tracenode *root_data = container_of(root, struct Tracenode, node);
	if (key_type == KEY_SYMBOL) {
		return strcmp(root_data->symbol, key);
	} else {
		return (long long)root_data->addr - (long long)key;
	}
}

static void free_tracenode_record(struct Tracenode *tracenode) {
	free(tracenode->record);
	tracenode->record = NULL;
}

static void free_tracenode(struct Tracenode *tracenode) {
	struct Tracenode *parent = tracenode->parent;
	struct TreeNode *tree_root = &parent->children->node;

	get_remove_tree_node(&tree_root, tracenode->key, compTracenode);

	// TODO: This tree looks ugly
	if (tree_root) {
		parent->children = container_of(tree_root, struct Tracenode, node);
	} else {
		parent->children = NULL;
	}

	free(tracenode);
}

static int is_droppable_record(struct Record *record) {
	if (record->pages_alloc == 0 && record->pages_alloc_peak < trivial_peak_limit) {
		return 1;
	}

	return 0;
}

static int tracenode_gc(struct Tracenode *tracenode) {
	/* Ensure record is either dropped or droppable */
	int ret = 0;
	if (tracenode->record) {
		if (is_droppable_record(tracenode->record)) {
			free_tracenode_record(tracenode);
			ret = 1;
		} else {
			return 0;
		}
	}

	/* Only clean up record for top nodes */
	if (!tracenode->parent) {
		tracenode->record = NULL;
		return 0;
	}

	if (!tracenode->children) {
		free_tracenode(tracenode);
		ret = 1;
	}

	return ret;
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

			/* This may happen due to missing event */
			if (tracenode->record->pages_alloc < 0)
				tracenode->record->pages_alloc = 0;
		}

		if (!tracenode_gc(tracenode) &&
				!page_free_always_backtrack)
			break;

		tracenode = parent;
	}
}

/*
 * Record that pages is being freed by a tracenode
 * Should only be called against top of the stack
 */
static void record_page_free(unsigned long pfn_start, unsigned long nr_pages) {
	struct Tracenode *tracenode, *last = NULL;
	unsigned long pfn_off;

	pfn_off = pfn_start;

	while (nr_pages--) {
		tracenode = page_map[pfn_off].tracenode;

		if (last != tracenode) {
			if (last)
				do_record_page_free(last, pfn_off - pfn_start);
			page_free_counter += pfn_off - pfn_start;
			pfn_start = pfn_off;
			last = tracenode;
		}

		page_map[pfn_off++].tracenode = NULL;
	}

	if (last)
		do_record_page_free(last, pfn_off - pfn_start);
}

/*
 * Record that a memory region is being allocated by a tracenode
 * Should only be called against top of the stack
 */
static void record_page_alloc(struct Tracenode *root, unsigned long pfn_start, unsigned long nr_pages) {
	unsigned long pfn_off;
	struct Record *record = root->record;
	struct Tracenode *last_missed_tracenode = NULL;

	page_alloc_counter += nr_pages;
	record->pages_alloc += nr_pages;
	if (record->pages_alloc > record->pages_alloc_peak) {
		record->pages_alloc_peak = record->pages_alloc;
	}

	pfn_off = pfn_start;
	while (nr_pages--) {
		if (last_missed_tracenode != page_map[pfn_off].tracenode) {
			if (last_missed_tracenode)
				do_record_page_free(last_missed_tracenode, pfn_off - pfn_start);
			pfn_start = pfn_off;
			last_missed_tracenode = page_map[pfn_off].tracenode;
		}

		page_map[pfn_off++].tracenode = root;
	}

	if (last_missed_tracenode)
		do_record_page_free(last_missed_tracenode, pfn_off - pfn_start);
}

static void do_update_record(struct Tracenode *tracenode, struct PageEvent *pevent) {
	if (pevent->pages_alloc > 0) {
		if (pevent->pfn + pevent->pages_alloc >= max_pfn) {
			log_error ("BUG: Alloc pfn %lu out of max_pfn %lu\n", pevent->pfn + pevent->pages_alloc, max_pfn);
			return;
		}

		if (!tracenode) {
			log_debug("BUG: Page alloc event with NULL tracenode\n");
			return;
		}

		record_page_alloc(tracenode, pevent->pfn, pevent->pages_alloc);
	} else if (pevent->pages_alloc < 0) {
		if (pevent->pfn + -pevent->pages_alloc >= max_pfn) {
			log_error ("BUG: Free pfn %lu out of max_pfn %lu\n", pevent->pfn + -pevent->pages_alloc, max_pfn);
			return;
		}

		record_page_free(pevent->pfn, 0 - pevent->pages_alloc);
	} else {
		log_debug("BUG: Empty Event\n");
	}
}

void update_record(struct PageEvent *pevent) {
	do_update_record(NULL, pevent);
}

void update_tracenode_record(struct Tracenode *tracenode, struct PageEvent *pevent) {
	if (!tracenode->record) {
		tracenode->record = calloc(1, sizeof(struct Record));
	}

	do_update_record(tracenode, pevent);
}

void update_tracenode_record_shallow(struct Tracenode *tracenode, struct PageEvent *pevent) {
	struct Record *record = tracenode->record;
	if (record) {
		record->pages_alloc += pevent->pages_alloc;
		if (record->pages_alloc > record->pages_alloc_peak) {
			record->pages_alloc_peak = record->pages_alloc;
		}
	}
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

		if (is_tracenode_extended(root))
			populate_tracenode(tracenode);

		insert_child_tracenode(root, tracenode);
	}

	return tracenode;
}

static struct Task* new_task(long pid) {
	struct Task *task = (struct Task*)calloc(1, sizeof(struct Task));
	task->pid = pid;

	insert_hash_node(&active_task_map, &task->node, &pid);

	return task;
}

struct Task* try_get_task(long pid) {
	struct HashNode *hnode;
	hnode = get_hash_node(&active_task_map, &pid);

	if (hnode) {
		return container_of(
				hnode,
				struct Task,
				node);
	} else {
		return NULL;
	}
};

struct Task* task_exit(long pid) {
	struct HashNode *hnode;
	hnode = get_remove_hash_node(&active_task_map, &pid);

	if (hnode) {
		return container_of(
				hnode,
				struct Task,
				node);
	} else {
		return NULL;
	}
}

struct Task* get_or_new_task(long pid) {
	struct Task *task;
	task = try_get_task(pid);

	if (!task) {
		task = new_task(pid);
		refresh_task_name(task);
	}

	return task;
};

struct Task* get_or_new_task_with_name(long pid, char* name) {
	struct Task *task;
	task = try_get_task(pid);

	if (!task) {
		task = new_task(pid);
	} else if (task->task_name) {
		if (strcmp(task->task_name, name)) {
			/* If name is different, consider previous task exited */
			task_exit(pid);
			task = new_task(pid);
		} else {
			return task;
		}
	}

	task->task_name = strdup(name);
	return task;
};

void refresh_task_name(struct Task* task) {
	if (task->task_name) {
		free(task->task_name);
		task->task_name = NULL;
	}

	task->task_name = get_process_name_by_pid(task->pid);
}

int get_total_tasks_num(void) {
	return active_task_map.size + exited_task_map.size;
}

int get_active_tasks_num(void) {
	return active_task_map.size;
}

struct json_marker {
	int indent;
	int count;
};

static int comp_symbol(const void *x, const void *y) {
	struct Symbol *sa = (struct Symbol*)x;
	struct Symbol *sb = (struct Symbol*)y;

	if (sa->addr > sb->addr)
		return 1;
	else if (sa->addr < sb->addr)
		return -1;
	else return 0;
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
	if (ret)
		return ret;

	if (have_left_child(root, node)) {
		ret = for_each_tracenode_ret(left_child(root, struct Tracenode, node),
				op, blob);
	}
	if (ret)
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

/*
 * Allocation info is usually only recorded at the tracenode represents the top
 * of stack for better performacne, need to collect the info before generate
 * report or read info out of a node
 */
static void do_populate_tracenode_iter(struct Tracenode* tracenode, void *blob) {
	struct Record *parent_record = (struct Record*)blob;

	if (tracenode->record) {
		parent_record->pages_alloc += tracenode->record->pages_alloc;
		parent_record->pages_alloc_peak += tracenode->record->pages_alloc_peak;
	} else if (tracenode->children) {
		tracenode->record = calloc(1, sizeof(struct Record));
		for_each_tracenode(tracenode->children, do_populate_tracenode_iter, tracenode->record);
	} else {
		log_error("BUG: Empty Tracenode\n");
	}
}

static void do_populate_tracenode_shallow_iter(struct Tracenode* tracenode, void *blob) {
	struct Record *root_record = (struct Record*)blob;

	if (tracenode->record) {
		root_record->pages_alloc += tracenode->record->pages_alloc;
		root_record->pages_alloc_peak += tracenode->record->pages_alloc_peak;
	} else if (tracenode->children) {
		for_each_tracenode(tracenode->children, do_populate_tracenode_shallow_iter, blob);
	} else {
		log_error("BUG: Empty Tracenode\n");
	}
}

void populate_tracenode(struct Tracenode* tracenode) {
	if (tracenode->record == NULL) {
		tracenode->record = calloc(1, sizeof(struct Record));
	} else {
		memset(tracenode->record, 0, sizeof(struct Record));
	}

	if (tracenode->children)
		for_each_tracenode(tracenode->children, do_populate_tracenode_iter, tracenode->record);
}

void populate_tracenode_shallow(struct Tracenode* tracenode) {
	if (tracenode->record == NULL) {
		tracenode->record = calloc(1, sizeof(struct Record));
	} else {
		return;
	}

	if (tracenode->children)
		for_each_tracenode(tracenode->children, do_populate_tracenode_shallow_iter, tracenode->record);
}

static void __populate_tracenode_shallow_iter(struct Tracenode *node, void *_) {
	populate_tracenode_shallow(node);
}

void extend_tracenode(struct Tracenode* tracenode) {
	if (tracenode->children)
		for_each_tracenode(tracenode->children,
				   __populate_tracenode_shallow_iter,
				   tracenode->record);
}

static void do_depopulate_tracenode_shallow_iter(struct Tracenode* tracenode, void *_) {
	if (tracenode->record && tracenode->children) {
		free_tracenode_record(tracenode);
	}
}

static void do_depopulate_tracenode_iter(struct Tracenode* tracenode, void *_) {
	if (tracenode->record && tracenode->children) {
		free_tracenode_record(tracenode);
		for_each_tracenode(tracenode->children, do_depopulate_tracenode_iter, NULL);
	}
}

void depopulate_tracenode(struct Tracenode* tracenode) {
	if (tracenode->record && tracenode->children) {
		free_tracenode_record(tracenode);
		for_each_tracenode(tracenode->children, do_depopulate_tracenode_iter, NULL);
	}
}

void depopulate_tracenode_shallow(struct Tracenode* tracenode) {
	if (tracenode->record && tracenode->children) {
		free_tracenode_record(tracenode);
		for_each_tracenode(tracenode->children,
				   do_depopulate_tracenode_shallow_iter,
				   NULL);
	}
}

void unextend_tracenode(struct Tracenode* tracenode) {
	if (tracenode->children)
		for_each_tracenode(tracenode->children,
				   do_depopulate_tracenode_shallow_iter,
				   NULL);
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

int get_tracenode_num(struct Tracenode *root) {
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

	*count = get_tracenode_num(root);
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

struct Task **collect_tasks_sorted(int shallow, int *count) {
	struct HashNode *hnode = NULL;
	struct Task **tasks;
	int i = 0;

	tasks = malloc(active_task_map.size * sizeof(struct Task*));
	for_each_hnode(&active_task_map, hnode) {
		tasks[i] = container_of(hnode, struct Task, node);

		if (shallow)
			populate_tracenode_shallow(to_tracenode(tasks[i]));
		else
			populate_tracenode(to_tracenode(tasks[i]));

		i++;
	}

	qsort((void*)tasks, active_task_map.size, sizeof(struct Task*), comp_task_mem);

	*count = active_task_map.size;
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

void print_tracenode(struct Tracenode* tracenode, int current_indent, int top_nr, int throttle) {
	int next_indent = current_indent + 2, counter, padding = current_indent;
	long page_limit;

	while (padding --)
		log_info(" ");

	log_info("%s", get_tracenode_symbol(tracenode));

	log_info(" Pages: %ld (peak: %ld)\n",
			tracenode->record->pages_alloc,
			tracenode->record->pages_alloc_peak);

	page_limit = tracenode->record->pages_alloc;

	if (throttle)
		page_limit = page_limit * throttle / 100;

	if (tracenode->children) {
		struct Tracenode **nodes;
		nodes = collect_tracenodes_sorted(tracenode->children, &counter, 1);
		if (top_nr > 0)
			counter = top_nr > counter ? counter : top_nr;
		for (int i = 0; i < counter && page_limit > 0; i++) {
			print_tracenode(nodes[i], next_indent, top_nr, throttle);
			page_limit -= nodes[i]->record->pages_alloc;
		}
		free(nodes);
	}
}

void print_task(struct Task* task, int top_nr, int throttle) {
	int counter;
	struct Tracenode *tn = &task->tracenode;
	struct Tracenode **nodes;

	log_info("%s Pages: %ld (peak: %ld)\n",
			task->task_name,
			tn->record->pages_alloc,
			tn->record->pages_alloc_peak);
	if (to_tracenode(task)->children) {
		nodes = collect_tracenodes_sorted(to_tracenode(task)->children, &counter, 1);
		if (top_nr > 0)
			counter = top_nr > counter ? counter : top_nr;
		for (int i = 0; i < counter; i++) {
			print_tracenode(nodes[i], 2, top_nr, throttle);
		}

		free(nodes);
	}
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
		if (node->record) {
			if (!leaf->record)
				leaf->record = calloc(1, sizeof(struct Record));
			leaf->record->pages_alloc += node->record->pages_alloc;
			leaf->record->pages_alloc_peak += node->record->pages_alloc_peak;
		} else {
			// DEBUG
			log_error("BUG\n");
			while (node) {
				log_error("%s, %p, %p\n", get_tracenode_symbol(node), node->children, node->record);
				node = node->parent;
			}
		}
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
		for_each_hnode(&active_task_map, hnode) {
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
