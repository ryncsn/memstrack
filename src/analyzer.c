#include "analyzer.h"
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#define MAX_PATH 4096

const char STACK_TRACE_SIGN[] = " => ";
const char STACK_TRACE_EVENT[] = "<stack trace>";
const char TRACE_FILE[] = "/sys/kernel/debug/tracing/trace_pipe";
const char TRACE_BASE[] = "/sys/kernel/debug/tracing";
const char TRACE_EVENTS[] = "kmem:kmem_cache_alloc";
const char TRACE_FILTER[] = "common_pid != %d";

struct HashMap TaskMap = {
	hashTask,
	compTask,
	NULL
};

FILE* trace_file = NULL;
int lookahead;
char line[MAX_LINE];
struct Task *current_task = NULL;
struct Event current_event;

int read_next_valid_line(char *buffer, int size) {
	char *ret = NULL;
	do {
		ret = fgets(buffer, size, trace_file);
	}
	while (ret && ret[0] == '#');
	if (strstr(buffer, "LOST"))
		printf("%s", buffer);
	return !!ret;
}

void task_map_debug() {
	for (int i = 0; i < HASH_BUCKET; i++) {
		if (TaskMap.buckets[i] != NULL) {
			printf("Bucket %d in use\n", i);
		}
	}
}

void set_trace(const char* value, const char* path) {
	printf("Setting %s to %s\n", value, path);
	char filename[MAX_PATH];
	sprintf(filename, "%s/%s", TRACE_BASE, path);
	FILE *file = fopen(filename, "w");
	fprintf(file, value);
	fclose(file);
}

void cleanup_trace() {
	set_trace("0", "tracing_on");
	set_trace("", "trace");
	set_trace("", "set_event");
	set_trace("0", "events/kmem/filter");
	set_trace("", "trace_options");
}

void setup_trace() {
	char buffer[MAX_PATH];
	sprintf(buffer, TRACE_FILTER, getpid());
	set_trace(TRACE_EVENTS, "set_event");
	set_trace(buffer, "events/kmem/filter");
	set_trace("4096", "saved_cmdlines_size");
	set_trace("1", "tracing_on");
	set_trace("", "trace");
	set_trace("stacktrace", "trace_options");
	set_trace("sym-offset", "trace_options");
	set_trace("print-parent", "trace_options");
}

void on_exit() {
	fclose(trace_file);
	cleanup_trace();
	// task_map_debug();
	print_all_tasks(&TaskMap);
	exit(0);
}

void on_signal(int signal) {
	printf("Signal\n");
	on_exit();
}

struct TraceNode* process_stacktrace() {
	lookahead = !!read_next_valid_line(line, MAX_LINE);
	if (!lookahead) {
		// EOF
		return NULL;
	}
	if (strncmp(line, STACK_TRACE_SIGN, sizeof(STACK_TRACE_SIGN) -1) != 0) {
		// Read ahead end of trace
		return NULL;
	}

	struct TraceNode *tp = NULL;
	char *callsite = NULL, *callsite_arg = NULL;
	int callsite_len = 0;
	callsite_arg = line + sizeof(STACK_TRACE_SIGN) - 1;
	callsite_len = strlen(callsite_arg);
	callsite = malloc(callsite_len + 1);
	strcpy(callsite, callsite_arg);
	callsite[callsite_len - 1] = '\0';

	// Process next traceline
	tp = process_stacktrace();

	if (tp == NULL) {
		tp = get_or_new_tracepoint(&current_task->tracepoints, callsite);
	} else {
		tp = get_or_new_tracepoint(&tp->tracepoints, callsite);
	}

	update_record(&tp->record, &current_event);

	free(callsite);
	return tp;
}

int main() {
	trace_file = fopen(TRACE_FILE, "r");
	setup_trace();
	signal(SIGINT, on_signal);
	while(lookahead || read_next_valid_line(line, MAX_LINE)){
		char *task_info = NULL, *event_info = NULL, *pid_arg = NULL;
		unsigned int pid = 0;

		lookahead = 0;
		task_info = line;
		event_info = strstr(line, ": ");

		while(task_info[0] == ' ' || task_info[0] == '\t') {
			task_info++;
		}

		if (event_info) {
			*event_info = '\0';
			event_info += 2;
		}

		pid_arg = strstr(task_info, "-");
		if (pid_arg) {
			pid_arg[0] = '\0';
			pid_arg++;
			sscanf(pid_arg, "%u", &pid);
		}

		if (!task_info || !event_info) {
			continue;
		}

		if (strncmp(event_info, STACK_TRACE_EVENT, sizeof(STACK_TRACE_EVENT) - 1) == 0) {
			process_stacktrace();
		} else {
			char *event, *callsite;
			unsigned long long ptr;

			current_event.event = strtok(event_info, " ");
			callsite = strtok(NULL, " ");

			current_task = get_or_new_task(&TaskMap, task_info, pid);

			if (strncmp(current_event.event, "kmem_cache_alloc:", strlen(current_event.event)) == 0) {
				char *ptr_arg, *bytes_req_arg, *bytes_alloc_arg;
				ptr_arg = strtok(NULL, " ") + sizeof("ptr=") - 1;
				bytes_req_arg = strtok(NULL, " ") + sizeof("bytes_req=") - 1;
				bytes_alloc_arg = strtok(NULL, " ") + sizeof("bytes_alloc=") - 1;

				sscanf(bytes_req_arg, "%u", &current_event.bytes_req);
				sscanf(bytes_alloc_arg, "%u", &current_event.bytes_alloc);

				if (ptr_arg[0] == '0') {
					sscanf(bytes_req_arg, "%llx", &ptr);
				}

				update_record(&current_task->record, &current_event);
			}
		}
	}
	on_exit();
}
