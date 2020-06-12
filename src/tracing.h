/*
 * tracing.h
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

#include "utils.h"
#ifndef _MEMORY_TRACER_TRACING_LIB

#define to_tracenode(task_or_module_p) (&task_or_module_p->tracenode)
#define is_task(tracenode_p) (tracenode_p->parent == NULL)
#define is_stacktop(tracenode_p) (tracenode_p->children == NULL)
// TODO: Remove redundant record, and when alloc happened extending a stacktop, remove old record and inherit.

typedef void* trace_addr_t;

extern struct HashMap task_map, module_map;

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
	struct Tracenode tracenode;
	struct HashNode node;

	// TODO: Distinguish exited task
	long pid;
	char *task_name;
	char *module_loading;
};

struct Module {
	struct Tracenode tracenode;
	struct HashNode node;

	char *name;
	unsigned int pages;
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
void need_page_free_always_backtrack(void);

char* kaddr_to_sym(trace_addr_t addr);
char* kaddr_to_module(trace_addr_t addr);
char* get_tracenode_symbol(struct Tracenode *node);

void populate_tracenode_shallow(struct Tracenode* tracenode);
void populate_tracenode(struct Tracenode* tracenode);
void depopulate_tracenode(struct Tracenode* tracenode);

struct Tracenode* get_child_tracenode(struct Tracenode *root, void *key);
struct Tracenode* get_or_new_child_tracenode(struct Tracenode *root, void *key);
struct Task* get_or_new_task(char* task_name, int pid);
struct Task **collect_tasks_sorted(int shallow);
struct Module **collect_modules_sorted(int shallow);
struct Tracenode **collect_tracenodes_sorted(struct Tracenode *root, int *counter, int shallow);
struct Module *get_or_new_module(char *name);

void print_tracenode(struct Tracenode* tracenode, int indent, int substack_limit, int throttle);
void print_tracenode_json(struct Tracenode* tracenode, void *blob);

void print_task(struct Task* task);
void print_task_json(struct Task* task);

int for_each_tracenode_ret(struct Tracenode* root, int (*op)(struct Tracenode *node, void *blob), void *blob);
void for_each_tracenode(struct Tracenode* root, void (*op)(struct Tracenode *node, void *blob), void *blob);

#define _MEMORY_TRACER_TRACING_LIB 1

#endif /* ifndef _MEMORY_TRACER_TRACING_LIB */
