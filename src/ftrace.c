#include "memstrack.h"
#include "ftrace.h"
#include <string.h>
#include <unistd.h>

#define FTRACE_MAX_PATH 4096

char FTRACE_STACK_TRACE_SIGN[] = " => ";
char FTRACE_STACK_TRACE_EVENT[] = "<stack trace>";

#define TRACE_FILE "/sys/kernel/debug/tracing/trace_pipe"
#define TRACE_BASE "/sys/kernel/debug/tracing"
#define TRACE_FILTER "common_pid != %d"

static void set_trace(const char* value, const char* path) {
	log_debug("Setting %s to %s\n", value, path);
	char filename[FTRACE_MAX_PATH];
	sprintf(filename, "%s/%s", TRACE_BASE, path);
	FILE *file = fopen(filename, "w");
	fprintf(file, "%s", value);
	fclose(file);
}

int ftrace_read_next_valid_line(char *buffer, int size, FILE *trace_file) {
	char *ret = NULL;
	do {
		ret = fgets(buffer, size, trace_file);
	}
	while (ret && ret[0] == '#');
	if (strstr(buffer, "LOST")) {
		log_error("%s", buffer);
	}
	return !!ret;
}

int ftrace_cleanup(FILE **file) {
	set_trace("0", "tracing_on");
	set_trace("", "trace");
	set_trace("", "set_event");
	set_trace("0", "events/kmem/filter");
	set_trace("", "trace_options");
	fclose(*file);
	return 0;
}

int ftrace_setup(FILE **file, const char* trace_events) {
	char buffer[FTRACE_MAX_PATH];
	sprintf(buffer, TRACE_FILTER, getpid());
	set_trace(trace_events, "set_event");
	set_trace(buffer, "events/kmem/filter");
	set_trace("4096", "saved_cmdlines_size");
	set_trace("1", "tracing_on");
	set_trace("", "trace");
	set_trace("stacktrace", "trace_options");
	set_trace("sym-offset", "trace_options");
	set_trace("print-parent", "trace_options");
	*file = fopen(TRACE_FILE, "r");
	return 0;
}
