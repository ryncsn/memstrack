#include "tracing.h"

extern int perf_events_num;
extern struct PerfEvent *perf_events;

int perf_handling_init();
int perf_handling_clean();
int perf_handling_start();
int perf_handling_process(struct Context *context);
