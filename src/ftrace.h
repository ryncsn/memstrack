#include <stdio.h>

extern char FTRACE_STACK_TRACE_SIGN[];
extern char FTRACE_STACK_TRACE_EVENT[];

extern int ftrace_read_next_valid_line(char *buffer, int size, FILE *trace_file);
extern int ftrace_cleanup(FILE **file);
extern int ftrace_setup(FILE **file);
