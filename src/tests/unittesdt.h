/* unittest.h
 *
 * Basic boilerplate, one test per file
 *
 */

#ifndef MEMSTRACK_UNITTEST_H
#undef NDEBUG
#define MEMSTRACK_UNITTEST_H 1

#include <stdlib.h>
#include <stdarg.h>
#include <execinfo.h>
#include <assert.h>

#include "../memstrack.h"
#include "../tracing.h"

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

void dump_task(struct Task *task) {
	printf("Task %s: page_alloc: %ld, peak_alloc_peak: %ld\n",
			task->task_name,
			to_tracenode(task)->record->pages_alloc,
			to_tracenode(task)->record->pages_alloc_peak);
}

void dump_tracenode(struct Tracenode *node) {
	printf("Tracenode %lx: page_alloc: %ld, peak_alloc_peak: %ld\n",
			(unsigned long)node->addr,
			node->record->pages_alloc,
			node->record->pages_alloc_peak);
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

#define UNITTEST(test_name, test_func)\
int main(int argc, char *argv[])\
{\
	int ret;\
	printf("Running test: %s\n", test_name);\
	ret = test_func();\
	if (ret) {\
		printf("Test failed: %s\n", test_name);\
		return ret;\
	} else {\
		printf("Test passed: %s\n", test_name);\
		return 0;\
	}\
}
#endif
