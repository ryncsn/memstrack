#include <stdlib.h>
#include <stdarg.h>
#include <execinfo.h>
#include <assert.h>
#include "../memstrack.h"
#include "../tracing.h"

#undef NDEBUG

int empty_record(void) {
	struct Task* task;
	struct Tracenode* tracenode;
	struct PageEvent event = {
		1024,
		1024
	};
	struct Task** tasks;

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

int m_log(int level, const char *__restrict fmt, ...){
	if (level <= LOG_LVL_DEBUG) {
		return 0;
	}

	int ret;
	va_list args;
	va_start (args, fmt);
	ret = vfprintf(stderr, fmt, args);
	va_end (args);
	return ret;
}

void print_backtrace(void){
	char bt_buffer[4096];
	char **bt_string;
	int bt_count;

	bt_count = backtrace((void **)(&bt_buffer), 4096);
	bt_string = backtrace_symbols((void **)(&bt_buffer), bt_count);

	for (int i = 0; i < bt_count; i++) {
		printf("%s\n", bt_string[i]);
	}
}

int main(int argc, char *argv[])
{
	int ret;

	printf("Running test: %s\n", "Single Task");

	mem_tracing_init();

	ret = empty_record();

	if (ret) {
		printf("Test failed: %s\n", "Single Task");
		return ret;
	} else {
		printf("Test passed: %s\n", "Single Task");
		return 0;
	}
}
