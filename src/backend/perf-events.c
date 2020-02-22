#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/sysinfo.h>
#include <linux/perf_event.h>

#include "perf-internal.h"
#include "perf-events-define.h"

#include "../memstrack.h"
#include "../tracing.h"

#define PERF_EVENTS_PATH "/sys/kernel/debug/tracing/events"
#define PERF_EVENTS_PATH_ALT "/sys/kernel/tracing/events"

DefineEvent(
	kmem, mm_page_alloc,
	IncludeCommonEventFields(),
	EventField(unsigned int, order),
	EventField(unsigned long, pfn),
	EventField(struct page *, page),
	// EventField(gfp_t, gtp_flags),
	EventField(int, migratetype)
);

DefineEvent(
	kmem, mm_page_free,
	IncludeCommonEventFields(),
	EventField(unsigned int, order),
	EventField(unsigned long, pfn)
);

DefineEvent(
	module, module_load,
	IncludeCommonEventFields(),
	EventField(int, taints),
	EventField(__data_loc char, name, 4, 1));

DefineEvent(
	syscalls, sys_enter_init_module,
	IncludeCommonEventFields(),
	EventField(int, __syscall_nr),
	EventField(struct page *, page));

static struct Tracenode* __process_stacktrace(
		struct perf_sample_callchain *callchain,
		struct Task *task, struct PageEvent *event)
{
	struct Tracenode *tp = to_tracenode(task);

	for (int i = 1; i < (int)callchain->nr; i++) {
		trace_addr_t addr = (trace_addr_t) *((&callchain->ips) + ((int)callchain->nr - i));
		try_update_record(tp, event);

		if (i == 1) {
			tp = get_or_new_child_tracenode(to_tracenode(task), addr);
		} else {
			tp = get_or_new_child_tracenode(tp, addr);
		}
	}

	update_record(tp, event);
	return tp;
}

static void __process_common(struct PerfEventRing *ring, const unsigned char* header,
		struct perf_sample_basic **body, struct perf_sample_callchain **callchain,
		struct perf_sample_raw **raw) {
	ring->counter++;

	*body = (struct perf_sample_basic*)header;
	header += sizeof(struct perf_sample_basic);

	*callchain = (struct perf_sample_callchain*)header;
	header += sizeof((*callchain)->nr) + sizeof((*callchain)->ips) * (*callchain)->nr;

	*raw = (struct perf_sample_raw*)header;
	//header += sizeof((*raw)->size) + (*raw)->size;

	//return header;
}

static int perf_handle_mm_page_alloc(struct PerfEventRing *ring, const unsigned char* header) {
	struct Task *task;
	struct PageEvent event;

	struct perf_sample_basic *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;

	__process_common(ring, header, &body, &callchain, &raw);

	if (get_perf_event_info(mm_page_alloc)->page_info.checked) {
		// TODO: Older kernel won't work yet
	} else {
		unsigned long pfn = read_data_from_perf_raw(mm_page_alloc, pfn, unsigned long, raw);
		unsigned int order = read_data_from_perf_raw(mm_page_alloc, order, unsigned long, raw);

		event.pages_alloc = 1;
		event.pfn = pfn;

		for (unsigned int i = 0; i < order; ++i) {
			event.pages_alloc *= 2;
		}

		task = get_or_new_task(&task_map, NULL, body->pid);
		__process_stacktrace(callchain, task, &event);
	}

	return 0;
}

static int perf_handle_mm_page_free(struct PerfEventRing *ring, const unsigned char* header) {
	struct PageEvent event;

	struct perf_sample_basic *body;
	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;

	__process_common(ring, header, &body, &callchain, &raw);

	unsigned long pfn = read_data_from_perf_raw(mm_page_free, pfn, unsigned long, raw);
	unsigned int order = read_data_from_perf_raw(mm_page_free, order, unsigned int, raw);

	event.pages_alloc = -1;
	event.pfn = pfn;

	for (unsigned int i = 0; i < order; ++i) {
		event.pages_alloc *= 2;
	}

	// TODO: not tracking task here
	update_record(NULL, &event);

	return 0;
}

static int always_enable(void) { return 1; }

const struct perf_event_table_entry perf_event_table[] = {
	{ &get_perf_event(mm_page_alloc),	perf_handle_mm_page_alloc,	always_enable },
	{ &get_perf_event(mm_page_free),	perf_handle_mm_page_free,	always_enable },
};

const int perf_event_entry_number = sizeof(perf_event_table) / sizeof(struct perf_event_table_entry);

int perf_load_events(void)
{
	int ret;

	for (int i = 0; i < perf_event_entry_number; ++i) {
		ret = perf_do_load_event_info(perf_event_table[i].event);
		if (ret)
			return ret;
	}

	return 0;
}

int perf_ring_setup(struct PerfEventRing *ring) {
	struct perf_event_attr attr;
	int perf_fd = 0, mmap_size = 0;

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_period = 1;
	attr.sample_type = SAMPLE_CONFIG_FLAG;
	attr.sample_id_all = 1;

	attr.disabled = 1;
	attr.exclude_callchain_user = 1;
	attr.exclude_callchain_kernel = 0;
	attr.config = ring->event->id;

	mmap_size = (CPU_BUFSIZE + 1) * page_size;

	attr.wakeup_watermark = mmap_size / 4;
	if (attr.wakeup_watermark < (__u32)page_size) {
		log_error("perf ring buffer too small!\n");
	}
	attr.watermark = 1;

	perf_fd = sys_perf_event_open(&attr, -1, ring->cpu, -1, 0);

	if (perf_fd <= 0) {
		log_error("Error calling perf_event_open: %s\n", strerror(errno));
		return errno;
	}

	fcntl(perf_fd, F_SETFL, O_NONBLOCK);

	// Extra one page for metadata
	void *perf_mmap = mmap(NULL,
			mmap_size ,
			PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);

	if (perf_mmap == MAP_FAILED) {
		log_error("Failed mmaping perf ring buffer: %s\n", strerror(errno));
		return errno;
	}

	ring->fd = perf_fd;
	ring->mmap_size = mmap_size;
	ring->data_size = mmap_size - page_size;
	ring->meta = (struct perf_event_mmap_page *)perf_mmap;
	ring->data = (unsigned char *)perf_mmap + page_size;
	ring->index = 0;

	return 0;
}

int perf_ring_start_sampling(struct PerfEventRing *ring) {
	int ret;
	char buffer[1024];
	sprintf(buffer, "common_pid!=%d", getpid());

	log_debug("Starting sampling on perf fd %d\n", ring->fd);
	ret = ioctl(ring->fd, PERF_EVENT_IOC_RESET, 0);
	if (ret) {
		log_error("Failed to reset perf sampling!\n");
	}

	ret = ioctl(ring->fd, PERF_EVENT_IOC_SET_FILTER, buffer);
	if (ret) {
		log_error("Failed apply event filter!\n");
	}

	ret = ioctl(ring->fd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret) {
		log_error("Failed to start perf sampling!\n");
	}

	return ret;
}

static int perf_handle_sample(struct PerfEventRing *ring, const unsigned char* header) {
	struct perf_sample_basic *body = (struct perf_sample_basic*)header;
	log_debug("Event: %s", ring->event->name);

	if (SAMPLE_CONFIG_FLAG & PERF_SAMPLE_TID & PERF_SAMPLE_CPU) {
		log_debug(" on PID %d, TID %d, CPU %d, RES %d\n", ring->event->name, body->pid, body->tid, body->cpu, body->res);
	} else {
		log_debug("\n");
	}

	header += sizeof(*body);

	if (SAMPLE_CONFIG_FLAG & PERF_SAMPLE_CALLCHAIN) {
		struct perf_sample_callchain *callchain = (struct perf_sample_callchain*)header;
		log_debug("Callchain size: %lu\n", callchain->nr);
		header += sizeof(callchain->nr);
		for (int i = 0; i < (int)callchain->nr; i++) {
			log_debug("IP: %lx\n", *((&callchain->ips) + i));
			header += sizeof(callchain->ips);
		}
	}

	if (SAMPLE_CONFIG_FLAG & PERF_SAMPLE_RAW) {
		struct perf_sample_raw *raw = (struct perf_sample_raw*)header;
		log_debug("Raw data size: %u\n", raw->size);

		unsigned char *raw_data = (unsigned char*)(&raw->data);
		for (int i = 0; i < (int)raw->size; ++i) {
			log_debug("Raw data[%d]: 0x%x\n", i, raw_data[i]);
		}
	}

	return 0;
}

static int perf_handle_lost_event(const unsigned char* header) {
	struct perf_lost_events *body = (struct perf_lost_events*)header;
	log_warn("Lost %d events on CPU %d!\n", body->lost, body->sample_id.cpu);
	return 0;
}

int perf_ring_process(struct PerfEventRing *perf_event) {
	unsigned char* data;
	struct perf_event_header *header;
	struct perf_event_mmap_page *meta;
	meta = perf_event->meta;

	while (meta->data_tail != meta->data_head) {
		data = perf_event->data + perf_event->index;
		header = (struct perf_event_header*)data;

		if (perf_event->index + sizeof(struct perf_event_header) < perf_event->data_size &&
				(perf_event->index + header->size) <= perf_event->data_size) {
			// FIXME: Droping overlapping event, causing tiny accuracy drop
			switch (header->type) {
				case PERF_RECORD_SAMPLE:
					if (perf_event->sample_handler) {
						perf_event->sample_handler(perf_event, data);
					} else {
						perf_handle_sample(perf_event, data);
					}
					break;
				case PERF_RECORD_LOST:
					perf_handle_lost_event(data);
					break;
					// case PERF_RECORD_MMAP:
					// case PERF_RECORD_FORK:
					// case PERF_RECORD_COMM:
					// case PERF_RECORD_EXIT:
					// case PERF_RECORD_THROTTLE:
					// case PERF_RECORD_UNTHROTTLE:
				default:
					log_warn("Unexpected event type %x!\n", header->type);
					break;
			}
		}

		meta->data_tail += header->size;
		perf_event->index += header->size;
		while (perf_event->index >= perf_event->data_size) {
			perf_event->index -= perf_event->data_size;
		}
	}
	return 0;
}

int perf_ring_clean(struct PerfEventRing *perf_event) {
	int ret;
	ret = ioctl(perf_event->fd, PERF_EVENT_IOC_DISABLE, 0);
	if (ret) {
		log_error("Failed to stop perf sampling!\n");
	}

	ret = munmap(perf_event->mmap, CPU_BUFSIZE);
	if (ret) {
		log_error("Failed to unmap perf ring buffer!\n");
	} else {
		perf_event->mmap = NULL;
		perf_event->data = NULL;
		perf_event->meta = NULL;
	}

	ret = close(perf_event->fd);
	if (ret) {
		log_error("Failed to close perf fd!\n");
	} else {
		perf_event->fd = -1;
	}

	return ret;
}
