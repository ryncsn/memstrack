#include "unittesdt.h"

int simple_allocation(void) {
	int task_num;
	struct Task* task;
	struct Tracenode* tracenode;
	struct PageEvent event = {
		1024,
		1024
	};
	struct Task** tasks;

	mem_tracing_init();

	task = get_or_new_task_with_name(1000,"task1");
	tracenode = get_or_new_child_tracenode(to_tracenode(task), (void*)0x100000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x110000);
	tracenode = get_or_new_child_tracenode(tracenode, (void*)0x111000);
	update_record(tracenode, &event);

	tasks = collect_tasks_sorted(0, &task_num);

	assert(task_num == 1);
	assert(to_tracenode(tasks[0])->record->pages_alloc == 1024);

	return 0;
}

UNITTEST("Simple Allocation", simple_allocation);
