/*
 * perf-events.c
 *
 * Copyright (C) 2020 Red Hat, Inc., Kairui Song <kasong@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>

#include "perf-internal.h"
#include "perf-events-define.h"

#include "../memstrack.h"
#include "../tracing.h"

#define PERF_EVENTS_PATH "/sys/kernel/debug/tracing/events"
#define PERF_EVENTS_PATH_ALT "/sys/kernel/tracing/events"
#define WAKEUP_WATERMARK 1024

DefineEvent(
	kmem, mm_page_alloc, 32,
	PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN,
	IncludeCommonEventFields(),
	EventField(unsigned int, order),
	EventField(unsigned long, pfn),
	EventField(struct page *, page),
	// EventField(gfp_t, gtp_flags),
	EventField(int, migratetype)
);

DefineEvent(
	kmem, mm_page_free, 32,
	PERF_SAMPLE_RAW,
	IncludeCommonEventFields(),
	EventField(unsigned int, order),
	EventField(unsigned long, pfn)
);

DefineEvent(
	module, module_load, 1,
	PERF_SAMPLE_RAW,
	IncludeCommonEventFields(),
	// EventField(int, taints),
	EventField(__data_loc char[], name, 4, 1));

DefineEvent(
	syscalls, sys_enter_init_module, 1,
	0,
	IncludeCommonEventFields());
	// EventField(int, __syscall_nr);

DefineEvent(
	syscalls, sys_exit_init_module, 1,
	0,
	IncludeCommonEventFields());
	// EventField(int, __syscall_nr);

DefineEvent(
	sched, sched_process_exec, 1,
	0,
	IncludeCommonEventFields());
	// EventField(int, __syscall_nr);

static unsigned char *trampo_page;

static struct Tracenode* __process_stacktrace_mod(
		struct perf_sample_callchain *callchain,
		struct Task *task, struct PageEvent *event, char *mod)
{
	struct Module *module = get_or_new_module(mod);
	struct Tracenode *tp = to_tracenode(module);

	for (int i = 1; i < (int)callchain->nr; i++) {
		trace_addr_t addr = (trace_addr_t) *((&callchain->ips) + ((int)callchain->nr - i));
		update_tracenode_record_shallow(tp, event);
		tp = get_or_new_child_tracenode(tp, addr);
	}

	update_tracenode_record(tp, event);
	return tp;
}

static struct Tracenode* __process_stacktrace(
		struct perf_sample_callchain *callchain,
		struct Task *task, struct PageEvent *event)
{
	if (task->module_loading) {
		return __process_stacktrace_mod(callchain, task, event, task->module_loading);
	}

	struct Tracenode *tp = to_tracenode(task);

	for (int i = 1; i < (int)callchain->nr; i++) {
		trace_addr_t addr = (trace_addr_t) *((&callchain->ips) + ((int)callchain->nr - i));
		update_tracenode_record_shallow(tp, event);
		tp = get_or_new_child_tracenode(tp, addr);
	}

	update_tracenode_record(tp, event);
	return tp;
}

static void __process_common(
		const unsigned char* header,
		struct perf_sample_callchain **callchain, struct perf_sample_raw **raw) {
	// struct perf_sample_basic *body = (struct perf_sample_basic*)header;

	*callchain = (struct perf_sample_callchain*)header;
	header += sizeof((*callchain)->nr) + sizeof((*callchain)->ips) * (*callchain)->nr;

	*raw = (struct perf_sample_raw*)header;
	//header += sizeof((*raw)->size) + (*raw)->size;

	//return header;
}

static int perf_handle_mm_page_alloc(const unsigned char* header) {
	struct Task *task;
	struct PageEvent event;

	struct perf_sample_callchain *callchain;
	struct perf_sample_raw *raw;

	callchain = (struct perf_sample_callchain*)(header + sizeof(struct perf_event_header));
	raw = (struct perf_sample_raw*)(header + sizeof(struct perf_event_header) +
			sizeof(callchain->nr) +
			sizeof(callchain->ips) * callchain->nr);

	unsigned long pfn = read_data_from_perf_raw(mm_page_alloc, pfn, unsigned long, raw);
	unsigned int order = read_data_from_perf_raw(mm_page_alloc, order, unsigned long, raw);
	int pid = read_data_from_perf_raw(mm_page_alloc, common_pid, int, raw);

	// TODO: pfn == -1?
	if (pfn == ULONG_MAX)
		return 0;

	event.pages_alloc = 1;
	event.pfn = pfn;

	for (unsigned int i = 0; i < order; ++i) {
		event.pages_alloc *= 2;
	}

	task = get_or_new_task(pid);

	__process_stacktrace(callchain, task, &event);

	return 0;
}

static int perf_handle_mm_page_free(const unsigned char* header) {
	struct PageEvent event;
	struct perf_sample_raw *raw;

	raw = (struct perf_sample_raw*)(header + sizeof(struct perf_event_header));

	unsigned long pfn = read_data_from_perf_raw(mm_page_free, pfn, unsigned long, raw);
	unsigned int order = read_data_from_perf_raw(mm_page_free, order, unsigned int, raw);

	// TODO: pfn == -1?
	if (pfn == ULONG_MAX)
		return 0;

	event.pages_alloc = -1;
	event.pfn = pfn;

	for (unsigned int i = 0; i < order; ++i) {
		event.pages_alloc *= 2;
	}

	update_record(&event);

	return 0;
}

static int perf_handle_module_load(const unsigned char* header) {
	struct Task *task;
	struct perf_sample_raw *raw;

	raw = (struct perf_sample_raw*)(header + sizeof(struct perf_event_header));

	struct data_loc_fixed {
		uint16_t offset;
		uint16_t size;
	} value = read_data_from_perf_raw(module_load, name, struct data_loc_fixed, raw);

	char *name = (char*)get_data_p_from_raw(raw) + value.offset;
	int pid = read_data_from_perf_raw(module_load, common_pid, int, raw);

	task = get_or_new_task(pid);
	task->module_loading = strdup(name);

	// TODO: On event lost, remove all module_loading
	log_debug("Module loading %s\n", name);

	return 0;
}

static int perf_handle_sys_exit_init_module(const unsigned char* header) {
	struct Task *task;
	struct perf_sample_raw *raw;

	raw = (struct perf_sample_raw*)(header + sizeof(struct perf_event_header));

	int pid = read_data_from_perf_raw(module_load, common_pid, int, raw);

	log_debug("Module loading exit\n");
	task = get_or_new_task(pid);
	if (!task->module_loading) {
		log_debug("Ignoring sys_exit_init_module of task %ld\n", task->pid);
	} else {
		free(task->module_loading);
		task->module_loading = NULL;
	}

	return 0;
}

static int perf_handle_process_exec(const unsigned char* header) {
	struct Task *task;
	struct perf_sample_raw *raw;

	raw = (struct perf_sample_raw*)(header + sizeof(struct perf_event_header));

	int pid = read_data_from_perf_raw(module_load, common_pid, int, raw);

	task = try_get_task(pid);
	if (task) {
		refresh_task_name(task);
	}

	return 0;
}

static int always_enable(void) { return 1; }

const struct perf_event_table_entry perf_event_table[] = {
	{ &get_perf_event(mm_page_alloc),		perf_handle_mm_page_alloc,		always_enable },
	{ &get_perf_event(mm_page_free),		perf_handle_mm_page_free,		always_enable },
	{ &get_perf_event(module_load),			perf_handle_module_load,		always_enable },
//	{ &get_perf_event(sys_enter_init_module),	perf_handle_module_load,		always_enable },
	{ &get_perf_event(sys_exit_init_module),	perf_handle_sys_exit_init_module,	always_enable },
	{ &get_perf_event(sched_process_exec),		perf_handle_process_exec,	always_enable },
};

const int perf_event_entry_number = sizeof(perf_event_table) / sizeof(struct perf_event_table_entry);

int perf_prepare_events(int buf_size)
{
	int ret;
	int perf_event_enabled_num = 0;
	int total_factor = 0;
	size_t buf_per_factor, aligned_buf_size = 0;

	for (int i = 0; i < perf_event_entry_number; ++i) {
		ret = perf_do_load_event_info(perf_event_table[i].event);
		if (ret)
			return ret;

		if (perf_event_table[i].is_enabled()) {
			perf_event_enabled_num ++;
			total_factor += perf_event_table[i].event->buf_factor;
		}
	}

	/* Check event requirements */
	if (get_perf_event_info(mm_page_alloc)->page_info.checked) {
		log_error("Current running kernel is too old and not supported.\n");
		return -1;
	}

	buf_size = buf_size / total_factor / page_size;
	if (buf_size == 0)
		buf_size = 1;
	buf_per_factor = buf_size * page_size;
	log_debug("Using buffer size %ldKB\n", buf_per_factor * total_factor / 1024);

	for (int i = 0; i < perf_event_entry_number; ++i) {
		size_t size = page_size, max_size = perf_event_table[i].event->buf_factor * buf_per_factor;

		if (max_size < WAKEUP_WATERMARK || max_size < page_size) {
			log_error("perf ring buffer too small!\n");
		}

		while (size < max_size)
			size *= 2;

		if (size > max_size)
			size /= 2;

		size += page_size;

		perf_event_table[i].event->buf_size = size;
		aligned_buf_size += size;

		log_debug("%s using %ld (%ld pages) of buffer per CPU.\n",
				perf_event_table[i].event->name,
				perf_event_table[i].event->buf_size,
				perf_event_table[i].event->buf_size / page_size);
	}

	log_debug("Perf buffer size aligned to %ld (%lxMB) per CPU.\n", aligned_buf_size, aligned_buf_size >> 20);

	return perf_event_enabled_num;
}

int perf_ring_setup(struct PerfEventRing *ring) {
	struct perf_event_attr attr;
	int perf_fd = 0;

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_period = 1;
	attr.sample_type = ring->event->sample_type;
	attr.sample_id_all = 1;

	attr.disabled = 1;
	attr.exclude_callchain_user = 1;
	attr.exclude_callchain_kernel = 0;
	attr.config = ring->event->id;

	/* Try wake up when there are 1KB of event to process */
	attr.wakeup_watermark = WAKEUP_WATERMARK;
	attr.watermark = 1;

	perf_fd = sys_perf_event_open(&attr, -1, ring->cpu, -1, 0);

	if (perf_fd <= 0) {
		log_error("Error calling perf_event_open: %s\n", strerror(errno));
		return errno;
	}

	fcntl(perf_fd, F_SETFL, O_NONBLOCK);

	// Extra one page for metadata
	void *perf_mmap = mmap(NULL, ring->event->buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);

	if (perf_mmap == MAP_FAILED) {
		log_error("Failed mmaping perf ring buffer: %s, %d\n", strerror(errno), ring->event->buf_size);
		return errno;
	}

	ring->fd = perf_fd;
	ring->mmap = perf_mmap;
	ring->data_size = ring->event->buf_size - page_size;
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

	trampo_page = malloc(page_size);

	return ret;
}

static int perf_debug_handler(struct PerfEventRing *ring, const unsigned char* header) {
	struct perf_event_header *body = (struct perf_event_header*)header;
	log_debug("Event: %s", ring->event->name);

	if (ring->event->sample_type & PERF_SAMPLE_TID & PERF_SAMPLE_CPU) {
		log_debug(" on CPU %d\n", ring->cpu);
	} else {
		log_debug("\n");
	}

	header += sizeof(*body);

	if (ring->event->sample_type & PERF_SAMPLE_CALLCHAIN) {
		struct perf_sample_callchain *callchain = (struct perf_sample_callchain*)header;
		log_debug("Callchain size: %lu\n", callchain->nr);
		header += sizeof(callchain->nr);
		for (int i = 0; i < (int)callchain->nr; i++) {
			log_debug("IP: %lx\n", *((&callchain->ips) + i));
			header += sizeof(callchain->ips);
		}
	}

	if (ring->event->sample_type & PERF_SAMPLE_RAW) {
		struct perf_sample_raw *raw = (struct perf_sample_raw*)header;
		log_debug("Raw data size: %u\n", raw->size);

		unsigned char *raw_data = (unsigned char*)(&raw->data);
		for (int i = 0; i < (int)raw->size; ++i) {
			log_debug("Raw data[%d]: 0x%x\n", i, raw_data[i]);
		}
	}

	return 0;
}

static int perf_handle_lost_event(const unsigned char* header, int cpu, char *event_name) {
	struct perf_lost_events *body = (struct perf_lost_events*)header;
	log_warn("Lost %lu %s events on CPU %d!\n", body->lost, event_name, cpu);
	return 0;
}

int perf_ring_process(struct PerfEventRing *ring) {
	struct perf_event_mmap_page *meta;
	struct perf_event_header *header;
	unsigned char *data;
	unsigned long off;

	meta = ring->meta;
	while (meta->data_tail != meta->data_head) {
		off = (unsigned long)(meta->data_tail & (ring->data_size - 1));
		data = ring->data + off;
		header = (void*)data;

		if (off + sizeof(struct perf_event_header) >= ring->data_size) {
			off = ring->data_size - off;
			memcpy(trampo_page, data, off);

			data = trampo_page + off;
			off = sizeof(struct perf_event_header) - off;
			memcpy(data, ring->data, off);

			header = (void*)trampo_page;
			if (header->size <= page_size) {
				memcpy(trampo_page + sizeof(struct perf_event_header),
				       ring->data + off,
				       header->size - sizeof(struct perf_event_header));
			} else {
				log_error("Event is too large\n");
				goto next;
			}
		} else if (off + header->size > ring->data_size) {
			if (header->size <= page_size) {
				off = ring->data_size - off;
				memcpy(trampo_page, data, off);
				memcpy(trampo_page + off, ring->data, (header->size - off));
			} else {
				log_error("Event is too large\n");
				goto next;
			}
			header = (void*)trampo_page;
		}

		switch (header->type) {
			case PERF_RECORD_SAMPLE:
				if (ring->sample_handler) {
					ring->sample_handler((void*)header);
				} else {
					perf_debug_handler(ring, (void*)header);
				}
				break;
			case PERF_RECORD_LOST:
				perf_handle_lost_event((void*)header, ring->cpu, ring->event->name);
				break;
				// TODO:
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

next:
		meta->data_tail += header->size;
	}
	return 0;
}

int perf_ring_clean(struct PerfEventRing *perf_event) {
	int ret;
	ret = ioctl(perf_event->fd, PERF_EVENT_IOC_DISABLE, 0);
	if (ret) {
		log_error("Failed to stop perf sampling!\n");
	}

	ret = munmap(perf_event->mmap, perf_event->event->buf_size);
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
