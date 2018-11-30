#include <stdio.h>

extern char FTRACE_STACK_TRACE_SIGN[];
extern char FTRACE_STACK_TRACE_EVENT[];

int ftrace_read_next_valid_line(char *buffer, int size, FILE *trace_file);
int ftrace_cleanup(FILE **file);
int ftrace_setup(FILE **file);
