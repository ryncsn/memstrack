#include "unittesdt.h"

int test(void) {
	struct Task* task;
	struct Tracenode* tracenode;
	struct PageEvent event = {
		1024,
		1024
	};
	struct Task** tasks;

	mem_tracing_init();

	/* Create 2 tasks, and alloc 4096 pages in total */
	task = get_or_new_task("task1", 1000);
	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x110000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x111000);
	update_record(tracenode, &event);

	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x110000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x111000);
	event.pfn += 1024;
	update_record(tracenode, &event);

	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x120000);
	event.pfn += 1024;
	update_record(tracenode, &event);

	task = get_or_new_task("task2", 1001);
	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x120000);
	event.pfn += 1024;
	update_record(tracenode, &event);

	tasks = collect_tasks_sorted(0);

	assert(task_map.size == 2);
	assert(to_tracenode(tasks[1])->record->pages_alloc == 1024);
	assert(to_tracenode(tasks[0])->record->pages_alloc == 3072);

	return 0;
}

UNITTEST("Multiple Allocation", test);
