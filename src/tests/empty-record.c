#include "unittesdt.h"

int test(void) {
	struct Task** tasks;

	mem_tracing_init();

	get_or_new_task("task1", 1000);
	tasks = collect_tasks_sorted(0);

	assert(task_map.size == 1);
	assert(to_tracenode(tasks[0])->record->pages_alloc == 0);

	return 0;
}

UNITTEST("Empty Record", test);
