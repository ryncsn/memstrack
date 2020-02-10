#include <stdio.h>
#include <poll.h>

#define FTRACE_MAX_LINE 4096

int ftrace_handling_init();
int ftrace_handling_clean();
int ftrace_handling_process();

static inline int ftrace_count_fds(void) { return 1; /* Only one ftrace reader */ }
int ftrace_apply_fds(struct pollfd *fds);