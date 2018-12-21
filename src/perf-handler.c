#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "memory-tracer.h"
#include "tracing.h"
#include "perf.h"

int perf_events_num;

struct PerfEvent *perf_events;

const unsigned char* __process_common(struct PerfEvent *perf_event, const unsigned char* header,
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

static void __process_stacktrace(struct perf_sample_callchain *callchain, void *blob) {
	struct TraceNode *tp = NULL;
	struct Context *context = (struct Context*)blob;
	for (int i = 1; i <= (int)callchain->nr; i++) {
		if (0xffffffffffffff80 == *((&callchain->ips) + ((int)callchain->nr - i))) {
			//FIXME
			continue;
		}
		if (i == 1) {
			update_record(&context->task->record, &context->event);
			tp = get_or_new_tracepoint_raw(&context->task->tracepoints, *((&callchain->ips) + ((int)callchain->nr - i)));
		} else {
			tp = get_or_new_tracepoint_raw(&tp->tracepoints, *((&callchain->ips) + ((int)callchain->nr - i)));
		}
		update_record(&tp->record, &context->event);
	}
}


int perf_handle_nothing(struct PerfEvent *perf_event, const unsigned char* header, void *blob) {
	perf_event->counter++;
	return 0;
}

int perf_handle_kmem_cache_alloc(struct PerfEvent *perf_event, const unsigned char* header, void *blob) {
	struct Context *context = (struct Context*)blob;
	perf_event->counter++;

	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_kmem_cache_alloc *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	context->task = get_or_new_task(&TaskMap, NULL, body->pid);
	context->event.bytes_req = raw_data->bytes_req;
	context->event.bytes_alloc = raw_data->bytes_alloc;
	context->event.pages_alloc = 0;

	__process_stacktrace(callchain, context);

	return 0;
}

int perf_handle_mm_page_alloc(struct PerfEvent *perf_event, const unsigned char* header, void *blob) {
	perf_event->counter++;
	struct Context *context = (struct Context*)blob;

	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_mm_page_alloc *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	context->task = get_or_new_task(&TaskMap, NULL, body->pid);
	context->event.bytes_req = 0;
	context->event.bytes_alloc = 0;
	context->event.pages_alloc = 1;

	struct TraceNode *tp = NULL;

	for (int i = 0; i < (int)raw_data->order; ++i) {
		context->event.pages_alloc *= 2;
	}

	__process_stacktrace(callchain, context);

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

int *PERF_EVENTS_ENABLE[] = {
	&memtrac_page,
	&memtrac_page,
	&memtrac_slab,
	&memtrac_slab,
};


int perf_handling_init() {
	int err = 0;
	const int cpu_num = get_perf_cpu_num();
	const int event_num = sizeof(PERF_EVENTS) / sizeof(const char*);
	for (int event = 0; event < event_num; event++){
		if (*PERF_EVENTS_ENABLE[event]) {
			perf_events_num += cpu_num;
		}
	}

	perf_events = (struct PerfEvent*)calloc(sizeof(struct PerfEvent), perf_events_num);

	int count = 0;
	for (int cpu = 0; cpu < cpu_num; cpu++) {
		for (int event = 0; event < event_num; event++){
			if (!*PERF_EVENTS_ENABLE[event]) {
				continue;
			}
			perf_events[count].event_id = get_perf_event_id(PERF_EVENTS[event]);
			if (perf_events[count].event_id < 0){
				log_error("Failed to retrive event id for \'%s\', please ensure tracefs is mounted\n", PERF_EVENTS[event]);
				err = EINVAL;
				break;
			}
			perf_events[count].cpu = cpu;
			perf_events[count].event_name = (char*)malloc(strlen(PERF_EVENTS[event]) + 1);
			if (perf_events[count].event_name == NULL){
				err = ENOMEM;
				break;
			}
			perf_events[count].sample_handler = PERF_EVENTS_HANDLERS[event];
			strcpy(perf_events[count].event_name, PERF_EVENTS[event]);
			count++;
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

int perf_handling_clean() {
	int i;
	for (i = 0; i < perf_events_num; i++) {
		perf_event_clean(perf_events + i);
	}
	return 0;
}

int perf_handling_start() {
	int err;
	for (int i = 0; i < perf_events_num; i++) {
		err = perf_event_start_sampling(perf_events + i);
		if (err) {
			log_error("Failed starting perf event sampling: %s!\n", strerror(err));
		}
	}
	return err;
}

int perf_handling_process(struct Context* context) {
	int err, i;
	struct pollfd *perf_fds = (struct pollfd*)calloc(sizeof(struct pollfd), perf_events_num);
	for (i = 0; i < perf_events_num; i++) {
		perf_fds[i].fd = perf_events[i].perf_fd;
		perf_fds[i].events = POLLIN;
	}
	poll(perf_fds, perf_events_num, 250);
	for (i = 0; i < perf_events_num; i++) {
		perf_event_process(perf_events + i, context);
	}
	return err;
}
