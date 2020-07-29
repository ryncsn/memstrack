#include "unittesdt.h"

int test(void) {
	int task_num;
	struct Task* task;
	struct Tracenode* tracenode;
	struct PageEvent event;
	struct Task** tasks;

	mem_tracing_init();

	task = get_or_new_task_with_name(1000, "task1");
	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x110000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x111000);
	event.pfn = 0;
	event.pages_alloc = 2048;
	update_tracenode_record(tracenode, &event);

	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x110000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x112000);
	event.pfn = 4096 + 2048;
	event.pages_alloc = 4096;
	update_tracenode_record(tracenode, &event);

	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x110000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x111000);
	event.pfn = 0;
	event.pages_alloc = -8192;
	update_tracenode_record(tracenode, &event);

	task = get_or_new_task_with_name(1001, "task2");
	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x120000);
	event.pfn = 4096 + 4096 + 2048 - 1024;
	event.pages_alloc = 1024;
	update_tracenode_record(tracenode, &event);

	tasks = collect_tasks_sorted(0, &task_num);

	dump_task(tasks[0]);
	dump_task(tasks[1]);

	assert(task_num == 2);
	assert(to_tracenode(tasks[0])->record->pages_alloc == 1024);
	assert(to_tracenode(tasks[1])->record->pages_alloc == 1024);

	return 0;
}

UNITTEST("Multiple Free", test);
