#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>

#include "memory-tracer.h"
#include "tracing.h"
#include "ftrace.h"
#include "perf.h"

#define MAX_LINE 4096

int memtrac_debug;
int memtrac_human;
int memtrac_perf;
int memtrac_ftrace;
int memtrac_json;

char* memtrac_perf_base;

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

int memtrac_log (int level, const char *__restrict fmt, ...){
	if (!memtrac_debug && level <= LOG_LVL_DEBUG) {
		return 0;
	}
	int ret;
	va_list args;
	va_start (args, fmt);
	if (level >= LOG_LVL_WARN) {
		ret = vfprintf(stderr, fmt, args);
	} else {
		ret = vfprintf(stdout, fmt, args);
	}
	va_end (args);
	return ret;
}

void task_map_debug() {
	log_debug("Task Bucket usage:\n");
	for (int i = 0; i < HASH_BUCKET; i++) {
		if (TaskMap.buckets[i] != NULL) {
			log_debug("Bucket %d in use\n", i);
		}
	}
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
	if (memtrac_debug) {
		task_map_debug();
	}
	print_all_tasks(&TaskMap);
	exit(0);
}

void on_signal(int signal) {
	log_warn("Exiting on signal %d\n", signal);
	on_exit();
}

const unsigned char* perf_handle_common(struct PerfEvent *perf_event, const unsigned char* header,
		struct perf_sample_fix **body, struct perf_sample_callchain **callchain,
		struct perf_sample_raw **raw, void **raw_data) {
	perf_event->counter++;

	*body = (struct perf_sample_fix*)header;
	header += sizeof(struct perf_sample_fix);

	*callchain = (struct perf_sample_callchain*)header;
	header += sizeof((*callchain)->nr) + sizeof((*callchain)->ips) * (*callchain)->nr;

	*raw = (struct perf_sample_raw*)header;
	*raw_data = (void*)&((*raw)->data);
	header += sizeof((*raw)->size) + (*raw)->size;

	return header;
}

void perf_handle_stacktrace(struct perf_sample_callchain *callchain) {
	struct TraceNode *tp = NULL;
	for (int i = 1; i <= (int)callchain->nr; i++) {
		if (0xffffffffffffff80 == *((&callchain->ips) + ((int)callchain->nr - i))) {
			//FIXME
			continue;
		}
		if (i == 1) {
			update_record(&current_task->record, &current_event);
			tp = get_or_new_tracepoint_raw(&current_task->tracepoints, *((&callchain->ips) + ((int)callchain->nr - i)));
		} else {
			tp = get_or_new_tracepoint_raw(&tp->tracepoints, *((&callchain->ips) + ((int)callchain->nr - i)));
		}
		update_record(&tp->record, &current_event);
	}
}


int perf_handle_nothing(struct PerfEvent *perf_event, const unsigned char* __) {
	perf_event->counter++;
	return 0;
}

int perf_handle_kmem_cache_alloc(struct PerfEvent *perf_event, const unsigned char* header) {
	perf_event->counter++;

	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_kmem_cache_alloc *raw_data;

	header = perf_handle_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	current_task = get_or_new_task(&TaskMap, NULL, body->pid);
	current_event.bytes_req = raw_data->bytes_req;
	current_event.bytes_alloc = raw_data->bytes_alloc;
	current_event.pages_alloc = 0;

	perf_handle_stacktrace(callchain);

	return 0;
}

int perf_handle_mm_page_alloc(struct PerfEvent *perf_event, const unsigned char* header) {
	perf_event->counter++;

	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_mm_page_alloc *raw_data;

	header = perf_handle_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	current_task = get_or_new_task(&TaskMap, NULL, body->pid);
	current_event.bytes_req = 0;
	current_event.bytes_alloc = 0;
	current_event.pages_alloc = 1;
	struct TraceNode *tp = NULL;

	for (int i = 0; i < (int)raw_data->order; ++i) {
		current_event.pages_alloc *= 2;
	}

	perf_handle_stacktrace(callchain);

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
	perf_handle_kmem_cache_alloc,
	perf_handle_nothing,
};

int perf_events_init() {
	int err = 0;
	const int cpu_num = get_perf_cpu_num();
	const int event_num = sizeof(PERF_EVENTS) / sizeof(const char*);

	perf_events_num = cpu_num * event_num;
	perf_events = (struct PerfEvent*)calloc(sizeof(struct PerfEvent), perf_events_num);

	for (int cpu = 0; cpu < cpu_num; cpu++) {
		for (int event = 0; event < event_num; event++){
			perf_events[cpu + event * cpu_num].event_id = get_perf_event_id(PERF_EVENTS[event]);
			if (perf_events[cpu + event * cpu_num].event_id == -1){
				log_error("Failed to retrive event id for \'%s\', please ensure tracefs is mounted\n", PERF_EVENTS[event]);
				err = EINVAL;
				break;
			}
			perf_events[cpu + event * cpu_num].cpu = cpu;
			perf_events[cpu + event * cpu_num].event_name = (char*)malloc(strlen(PERF_EVENTS[event]) + 1);
			if (perf_events[cpu + event * cpu_num].event_name == NULL){
				err = ENOMEM;
				break;
			}
			perf_events[cpu + event * cpu_num].sample_handler = PERF_EVENTS_HANDLERS[event];
			strcpy(perf_events[cpu + event * cpu_num].event_name, PERF_EVENTS[event]);
		}
	}

	for (int i = 0; i < perf_events_num; i++) {
		err = perf_event_setup(perf_events + i);
		if (err) {
			return err;
		}
	}

	return 0;
}

int ftrace_init() {
	return ftrace_setup(&ftrace_file);
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
	callsite = (char*)malloc(callsite_len + 1);
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
	int err;
	struct pollfd *perf_fds = (struct pollfd*)calloc(sizeof(struct pollfd), perf_events_num);
	for (int i = 0; i < perf_events_num; i++) {
		err = perf_event_start_sampling(perf_events + i);
		if (err) {
			log_error("Failed starting perf event sampling: %s!\n", strerror(err));
		}
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

static struct option long_options[] =
{
	/* These options set a flag. */
	{"ftrace",		no_argument,	&memtrac_ftrace,	1},
	{"perf",		no_argument,	&memtrac_perf,	1},
	// {"slab",		no_argument,	&memtrac_slab,	1},
	// {"page",		no_argument,	&memtrac_page,	1},
	// {"json",		no_argument,	&memtrac_json,	1},
	{"debug",		no_argument,		0,	'd'},
	// {"human-readable",	no_argument,		0,	'h'},
	// {"trace-base",		required_argument,	0,	'b'},
	// {"throttle-output",	required_argument,	0,	't'},
	{"help",		no_argument,	&memtrac_json,	'?'},
	{0, 0, 0, 0}
};


void display_usage() {
	log_info("Usage: memory-tracer [OPTION]... \n");
	log_info("    --debug		Print debug messages. \n");
	log_info("    --ftrace		Use ftrace for tracing, poor performance but should always work. \n");
	log_info("    --perf		Use binary perf for tracing, great performance, require CONFIG_FRAME_POINTER enabled. \n");
	// log_info("    --page		Collect page usage statistic. \n");
	// log_info("    --slab		Collect slab cache usage statistic. \n");
	// log_info("    --human-readable	Print sizes in a human reable way, eg bytes_alloc: 1048576 => 1M \n");
	// log_info("    --json		Format result as json. \n");
	// log_info("    --trace-base [DIR]	Use a different tracing mount path. \n");
	log_info("    --help 		Print this message. \n");
	// log_info("    --throttle-output [PERCENTAGE] \n");
	// log_info("    			Only print callsites consuming [PERCENTAGE] percent of total memory consumed. \n");
	// log_info("    			expect a number between 0 to 100. Useful to filter minor noises. \n");
}

int main(int argc, char **argv) {
	while (1) {
		int opt;
		int option_index = 0;

		opt = getopt_long(argc, argv, "db:h", long_options, &option_index);

		/* Detect the end of the options. */
		if (opt == -1)
			break;

		switch (opt)
		{
			case 0:
				// Flag setted, nothing to do
				break;
			case 'd':
				memtrac_debug = 1;
				break;
			case 'h':
				memtrac_human = 1;
				break;
			case 'b':
				memtrac_perf_base = (char*)calloc(sizeof(char), strlen(optarg) + 1);
				strcpy(memtrac_perf_base, optarg);
				break;
			case 't':
				// Not implemented
				break;
			case '?':
				display_usage();
				exit(0);
			default:
				display_usage();
				exit(1);
		}
	}

	if (memtrac_perf && memtrac_ftrace) {
		log_error("Can't have --ftrace and --perf set together!\n");
		exit(EINVAL);
	}

	if (!memtrac_perf && !memtrac_ftrace) {
		memtrac_perf = 1;  // Use perf by default
	}

	if (memtrac_debug) {
		log_debug("Debug mode is on\n");
	}

	if (getuid() != 0) {
		log_error("This tool requires root permission to work.\n");
		exit(EPERM);
	}

	int err;
	if (memtrac_perf) {
		err = perf_events_init();
		if (err) {
			log_error("Failed initializing perf event buffer: %s!", strerror(err));
			exit(err);
		}
		signal(SIGINT, on_signal);
		do_process_perf();
	} else if (memtrac_ftrace) {
		err = ftrace_init();
		if (err) {
			log_error("Failed initializing perf event buffer: %s!", strerror(err));
			exit(err);
		}
		signal(SIGINT, on_signal);
		do_process_ftrace();
	} else if (0) {
		// TODO
	}
	on_exit();
}
