#include "analyzer.h"

const char STACK_TRACE_SIGN[] = " => ";
const char STACK_TRACE_EVENT[] = "<stack trace>";

int read_next_valid_line(char *buffer, int size) {
	char *ret = NULL;
	do {
		ret = fgets(buffer, size, stdin);
	}
	while (ret && ret[0] == '#');
	return !!ret;
}

struct HashMap TaskMap = {
	hashTask,
	compTask,
	NULL
};

void task_map_debug() {
	for (int i = 0; i < HASH_BUCKET; i++) {
		if (TaskMap.buckets[i] != NULL) {
			printf("Bucket %d in use\n", i);
		}
	}
}

int lookahead;
char line[MAX_LINE];
struct Task *current_task = NULL;
struct Event current_event;

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
	callsite[callsite_len] = '\0';

	// Process next traceline
	tp = process_stacktrace();

	if (tp == NULL) {
		// printf("Line\n");
		// printf("Current task points %llx\n", (unsigned long long)current_task->tracepoints);
		tp = get_or_new_tracepoint(&current_task->tracepoints, callsite);
		printf("Line %s\n", tp->callsite);
	} else {
		// printf("Line2\n");
		tp = get_or_new_tracepoint(&tp->tracepoints, callsite);
		// printf("Line2 %s\n", tp->callsite);
	}

	update_record(&tp->record, &current_event);

	free(callsite);
	return tp;
}

int main() {
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
			printf("Invalid line: \n%s\n", line);
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
	task_map_debug();
	print_all_tasks(&TaskMap);
	exit(0);
}
