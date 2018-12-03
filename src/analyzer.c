#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <string.h>

#include "analyzer.h"
#include "perf.h"
#include "ftrace.h"

#define MAX_LINE 4096

struct HashMap TaskMap = {
	hashTask,
	compTask,
	{NULL},
};

char* PidMap[65535];

// For perf
int perf_events_num;
struct PerfEvent *perf_events;

// For ftrace
FILE* ftrace_file = NULL;
char ftrace_line[MAX_LINE];
unsigned int lookahead;

// Share analyzing db
struct Task *current_task = NULL;
struct Event current_event;
int debug = 1;

void task_map_debug() {
	printf("Task Bucket usage:\n");
	for (int i = 0; i < HASH_BUCKET; i++) {
		if (TaskMap.buckets[i] != NULL) {
			printf("Bucket %d in use\n", i);
		}
	}
}

char* get_process_name_by_pid(const int pid)
{
	char* name = (char*)calloc(sizeof(char), 1024);
	if (name) {
		sprintf(name, "/proc/%d/cmdline", pid);
		FILE* f = fopen(name,"r");
		if (f) {
			size_t size;
			size = fread(name, sizeof(char), 1024, f);
			if (size > 0){
				if ('\n' == name[size - 1]) {
					name[size - 1]='\0';
				}
			}
			fclose(f);
		}
	}
	return name;
}

void on_exit() {
	if (ftrace_file) {
		ftrace_cleanup(&ftrace_file);
	}
	if (perf_events) {
		for (int i = 0; i < perf_events_num; i++) {
			perf_event_clean(perf_events + i);
		}
	}
	if (debug) {
		task_map_debug();
	}
	print_all_tasks(&TaskMap);
	exit(0);
}

void on_signal(int signal) {
	fprintf(stderr, "Exiting on signal %d\n", signal);
	on_exit();
}

int perf_handle_nothing(struct PerfEvent *perf_event, const unsigned char* __) {
	perf_event->counter++;
	return 0;
}

int perf_handle_mm_page_alloc(struct PerfEvent *perf_event, const unsigned char* header) {
	perf_event->counter++;

	struct perf_sample_fix *body = (struct perf_sample_fix*)header;
	header += sizeof(*body);

	struct perf_sample_callchain *callchain = (struct perf_sample_callchain*)header;
	header += sizeof(callchain->nr) + sizeof(callchain->ips) * callchain->nr;

	struct perf_sample_raw *raw = (struct perf_sample_raw*)header;
	struct perf_raw_mm_page_alloc *raw_data = (struct perf_raw_mm_page_alloc*)(&raw->data);

	char *cmdline = PidMap[body->pid];
	if (!cmdline) {
		cmdline = PidMap[body->pid] = get_process_name_by_pid(body->pid);
	}
	current_task = get_or_new_task(&TaskMap, cmdline, body->pid);
	current_event.bytes_req = 0;
	current_event.bytes_alloc = 0;
	current_event.pages_alloc = 1;
	struct TraceNode *tp = NULL;
	for (int i = 0; i < (int)raw_data->order; ++i) {
		current_event.pages_alloc *= 2;
	}
	for (int i = 1; i <= (int)callchain->nr; i++) {
		if (i == 1) {
			update_record(&current_task->record, &current_event);
			tp = get_or_new_tracepoint_raw(&current_task->tracepoints, *((&callchain->ips) + ((int)callchain->nr - i)));
		} else {
			tp = get_or_new_tracepoint_raw(&tp->tracepoints, *((&callchain->ips) + ((int)callchain->nr - i)));
		}
		update_record(&tp->record, &current_event);
	}

	return 0;
}

const char *PERF_EVENTS[] = {
	"kmem:mm_page_alloc",
	"kmem:mm_page_free",
	"kmem:kmem_cache_alloc",
	"kmem:kmem_cache_free",
};

SampleHandler PERF_EVENTS_HANDLERS[] = {
	perf_handle_mm_page_alloc,
	perf_handle_nothing,
	perf_handle_nothing,
	perf_handle_nothing,
};

int perf_events_init() {
	const int cpu_num = get_perf_cpu_num();
	const int event_num = sizeof(PERF_EVENTS) / sizeof(const char*);

	perf_events_num = cpu_num * event_num;
	perf_events = calloc(sizeof(struct PerfEvent), perf_events_num);

	for (int cpu = 0; cpu < cpu_num; cpu++) {
		for (int event = 0; event < event_num; event++){
			perf_events[cpu + event * cpu_num].cpu = cpu;
			perf_events[cpu + event * cpu_num].event_name = malloc(strlen(PERF_EVENTS[event]) + 1);
			perf_events[cpu + event * cpu_num].event_id = get_perf_event_id(PERF_EVENTS[event]);
			perf_events[cpu + event * cpu_num].sample_handler = PERF_EVENTS_HANDLERS[event];
			strcpy(perf_events[cpu + event * cpu_num].event_name, PERF_EVENTS[event]);
		}
	}

	for (int i = 0; i < perf_events_num; i++) {
		perf_event_setup(perf_events + i);
	}

	return 0;
}

void ftrace_init() {
	ftrace_setup(&ftrace_file);
}

struct TraceNode* ftrace_process_stacktrace() {
	lookahead = !!ftrace_read_next_valid_line(ftrace_line, MAX_LINE, ftrace_file);
	if (!lookahead) {
		// EOF
		return NULL;
	}
	if (strncmp(ftrace_line, FTRACE_STACK_TRACE_SIGN, strlen(FTRACE_STACK_TRACE_SIGN) - 1) != 0) {
		// Read ahead end of trace
		return NULL;
	}

	struct TraceNode *tp = NULL;
	char *callsite = NULL, *callsite_arg = NULL;
	int callsite_len = 0;
	callsite_arg = ftrace_line + strlen(FTRACE_STACK_TRACE_SIGN);
	callsite_len = strlen(callsite_arg);
	callsite = malloc(callsite_len + 1);
	strcpy(callsite, callsite_arg);
	callsite[callsite_len - 1] = '\0';

	// Process next traceline
	tp = ftrace_process_stacktrace();

	if (tp == NULL) {
		tp = get_or_new_tracepoint(&current_task->tracepoints, callsite);
	} else {
		tp = get_or_new_tracepoint(&tp->tracepoints, callsite);
	}

	update_record(&tp->record, &current_event);

	free(callsite);
	return tp;
}

void do_process_perf() {
	struct pollfd *perf_fds = calloc(sizeof(struct pollfd), perf_events_num);
	for (int i = 0; i < perf_events_num; i++) {
		perf_event_start_sampling(perf_events + i);
	}

	while (1) {
		for (int i = 0; i < perf_events_num; i++) {
			perf_fds[i].fd = perf_events[i].perf_fd;
			perf_fds[i].events = POLLIN;
		}
		poll(perf_fds, perf_events_num, 250);
		for (int i = 0; i < perf_events_num; i++) {
			perf_event_process(perf_events + i);
		}
	}
}

void do_process_ftrace() {
	while(lookahead || ftrace_read_next_valid_line(ftrace_line, MAX_LINE, ftrace_file)){
		char *task_info = NULL, *event_info = NULL, *pid_arg = NULL;
		unsigned int pid = 0;

		lookahead = 0;
		task_info = ftrace_line;
		event_info = strstr(ftrace_line, ": ");

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

		if (strncmp(event_info, FTRACE_STACK_TRACE_EVENT, strlen(FTRACE_STACK_TRACE_EVENT) - 1) == 0) {
			ftrace_process_stacktrace();
		} else {
			// char *event, *callsite;
			unsigned long long ptr;

			current_event.event = strtok(event_info, " ");
			// callsite = strtok(NULL, " ");

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
}

int main() {
	if (1) {
		perf_events_init();
		signal(SIGINT, on_signal);
		do_process_perf();
	} else {
		ftrace_init();
		signal(SIGINT, on_signal);
		do_process_ftrace();
	}
		on_exit();
}
