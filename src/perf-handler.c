#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "memstrack.h"
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

static struct Tracenode* __process_stacktrace(
		struct perf_sample_callchain *callchain,
		struct Task *task, struct PageEvent *event)
{
	struct Tracenode *tp = NULL;

	for (int i = 1; i <= (int)callchain->nr; i++) {
		unsigned long addr = *((&callchain->ips) + ((int)callchain->nr - i));
		if (0xffffffffffffff80 == *((&callchain->ips) + ((int)callchain->nr - i))) {
			//FIXME
			continue;
		}
		if (i == 1) {
			tp = get_or_new_child_tracenode(&task->tracenode, NULL, addr);
		} else {
			tp = get_or_new_child_tracenode(tp, NULL, addr);
		}

		try_update_record(tp, event);
	}

	update_record(tp, event);
	return tp;
}

int perf_handle_nothing(struct PerfEvent *perf_event, const unsigned char* header) {
	perf_event->counter++;
	return 0;
}

int perf_handle_kfree(struct PerfEvent *perf_event, const unsigned char* header) {
	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_kfree *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	return 0;
}

int perf_handle_kmalloc(struct PerfEvent *perf_event, const unsigned char* header) {
	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_kmalloc *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	return 0;
}

int perf_handle_kmem_cache_free(struct PerfEvent *perf_event, const unsigned char* header) {
	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_kmem_cache_free *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	return 0;
}

int perf_handle_kmem_cache_alloc(struct PerfEvent *perf_event, const unsigned char* header) {
	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_kmem_cache_alloc *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	return 0;
}

int perf_handle_mm_page_alloc(struct PerfEvent *perf_event, const unsigned char* header) {
	struct PageEvent event;
	struct Task *task;

	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_mm_page_alloc *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	task = get_or_new_task(&TaskMap, NULL, body->pid);
	event.pages_alloc = 1;
	event.pfn = raw_data->pfn;

	for (int i = 0; i < (int)raw_data->order; ++i) {
		event.pages_alloc *= 2;
	}

	__process_stacktrace(callchain, task, &event);

	return 0;
}

int perf_handle_mm_page_free(struct PerfEvent *perf_event, const unsigned char* header) {
	struct PageEvent event;

	struct perf_sample_fix *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;
	struct perf_raw_mm_page_free *raw_data;

	header = __process_common(perf_event, header, &body, &callchain, &raw, (void**)&raw_data);

	event.pages_alloc = -1;
	event.pfn = raw_data->pfn;

	for (int i = 0; i < (int)raw_data->order; ++i) {
		event.pages_alloc *= 2;
	}

	// TODO: not tracking task here
	update_record(NULL, &event);

	return 0;
}

static int perf_tracks_page() {
	return m_page;
}

static int perf_tracks_slab() {
	return m_slab;
}

static struct perf_event_entry {
	char *name;
	int (*handler)(struct PerfEvent *perf_event, const unsigned char* header);
	int (*is_enabled)(void);
} const perf_event_table[] = {
	{ "kmem:kmalloc",         	perf_handle_kmalloc,         	perf_tracks_slab },
	{ "kmem:kfree",           	perf_handle_kfree,           	perf_tracks_slab },
	{ "kmem:mm_page_alloc",   	perf_handle_mm_page_alloc,   	perf_tracks_page },
	{ "kmem:mm_page_free",    	perf_handle_mm_page_free,    	perf_tracks_page },
	{ "kmem:kmem_cache_alloc",	perf_handle_kmem_cache_alloc,	perf_tracks_slab },
	{ "kmem:kmem_cache_free", 	perf_handle_kmem_cache_free, 	perf_tracks_slab },
};

struct pollfd *perf_fds;

const int perf_event_entry_number = sizeof(perf_event_table) / sizeof(struct perf_event_entry);

int perf_handling_init() {
	int err;
	int count = 0;
	int cpu_num = get_perf_cpu_num();
	const struct perf_event_entry *event;

	for (int i = 0; i < perf_event_entry_number; i++) {
		if (perf_event_table[i].is_enabled()) {
			perf_events_num += cpu_num;
		}
	}

	perf_events = (struct PerfEvent*)malloc(perf_events_num * sizeof(struct PerfEvent));

	for (int cpu = 0; cpu < cpu_num; cpu++) {
		for (int i = 0; i < perf_event_entry_number; i++){
			event = &perf_event_table[i];
			if (!event->is_enabled()) {
				continue;
			}
			perf_events[count].event_id = get_perf_event_id(event->name);
			if (perf_events[count].event_id < 0) {
				log_error("Failed to retrive event id for \'%s\', "
					  "please ensure tracefs is mounted\n", event->name);
				err = EINVAL;
				break;
			}
			perf_events[count].cpu = cpu;
			perf_events[count].event_name = (char*)malloc(strlen(event->name) + 1);
			if (perf_events[count].event_name == NULL){
				err = ENOMEM;
				break;
			}
			perf_events[count].sample_handler = event->handler;
			strcpy(perf_events[count].event_name, event->name);
			count++;
		}
	}

	for (int i = 0; i < perf_events_num; i++) {
		err = perf_event_setup(perf_events + i);
		if (err) {
			return err;
		}
	}

	perf_fds = (struct pollfd*)malloc(perf_events_num * sizeof(struct pollfd));
	for (int i = 0; i < perf_events_num; i++) {
		perf_fds[i].fd = perf_events[i].perf_fd;
		perf_fds[i].events = POLLIN;
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

int perf_handling_process_nb() {
	int err = 0, i;

	trace_count ++;
	for (i = 0; i < perf_events_num; i++) {
		err = perf_event_process(perf_events + i);
		if (err) {
			return err;
		}
	}
	return err;
}

int perf_handling_process() {
	poll(perf_fds, perf_events_num, 250);
	return perf_handling_process_nb();
}
