#include <poll.h>
#include "../tracing.h"

extern int perf_events_num;
extern struct PerfEvent *perf_events;
extern struct pollfd *perf_fds;

#define perf_fd_num perf_events_num

int perf_handling_init();
int perf_handling_clean();
int perf_handling_start();
int perf_handling_process();
int perf_handling_process_nb();
