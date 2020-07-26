#include "unittesdt.h"

int test(void) {
	int task_num;
	struct Task** tasks;

	mem_tracing_init();

	get_or_new_task_with_name(1000, "task1");
	tasks = collect_tasks_sorted(0, &task_num);

	assert(task_num == 1);
	assert(to_tracenode(tasks[0])->record->pages_alloc == 0);

	return 0;
}

UNITTEST("Empty Record", test);
