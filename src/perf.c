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

#include "memory-tracer.h"
#include "perf.h"

#define PERF_EVENTS_PATH "/sys/kernel/debug/tracing/events"
#define PERF_EVENTS_PATH_ALT "/sys/kernel/tracing/events"

static inline int sys_perf_event_open(struct perf_event_attr *attr,
		int pid, int cpu, int group_fd,
		unsigned long flags)
{
	log_debug("Opening perf event on CPU: %d event: %lld\n", cpu, attr->config);
	return syscall(__NR_perf_event_open, attr, pid, cpu,
			group_fd, flags);
}

int get_perf_cpu_num() {
	return get_nprocs();
}

unsigned int get_perf_event_id(const char* event) {
	char path_buffer[1024];
	char event_buffer[1024];
	char *event_group, *event_name;
	unsigned int event_id;

	strcpy(event_buffer, event);

	event_group = strtok(event_buffer, ":");
	event_name = strtok(NULL, ":");

	if(!event_group | !event_name) {
		return -EINVAL;
	}

	sprintf(path_buffer, "%s/%s/%s/id", PERF_EVENTS_PATH, event_group, event_name);
	FILE *id_file = fopen(path_buffer, "r");
	if (!id_file) {
		sprintf(path_buffer, "%s/%s/%s/id", PERF_EVENTS_PATH_ALT, event_group, event_name);
		id_file = fopen(path_buffer, "r");
	}
	if (!id_file) {
		return -ENOENT;
	}
	fscanf(id_file, "%u", &event_id);
	fclose(id_file);

	return event_id;
}

int perf_event_setup(struct PerfEvent *perf_event) {
	int perf_fd = 0, mmap_size = 0;
	struct perf_event_attr attr;

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_period = 1;
	attr.sample_type = SAMPLE_CONFIG_FLAG;

	attr.disabled = 1;
	attr.exclude_callchain_user = 1;
	attr.exclude_callchain_kernel = 0;
	attr.config = perf_event->event_id;

	mmap_size = (CPU_BUFSIZE + 1) * page_size;

	attr.wakeup_watermark = mmap_size / 4;
	if (attr.wakeup_watermark < (__u32)page_size) {
		log_error("perf ring buffer too small!\n");
	}
	attr.watermark = 1;

	perf_fd = sys_perf_event_open(&attr, -1, perf_event->cpu, -1, 0);

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

	perf_event->perf_fd = perf_fd;
	perf_event->mmap_size = mmap_size;
	perf_event->data_size = mmap_size - page_size;
	perf_event->meta = (struct perf_event_mmap_page *)perf_mmap;
	perf_event->data = (unsigned char *)perf_mmap + page_size;
	perf_event->index = 0;

	return 0;
}

int perf_event_start_sampling(struct PerfEvent *perf_event) {
	int ret;
	char buffer[1024];
	sprintf(buffer, "common_pid!=%d", getpid());

	log_debug("Starting sampling on perf fd %d\n", perf_event->perf_fd);
	ret = ioctl(perf_event->perf_fd, PERF_EVENT_IOC_RESET, 0);
	if (ret) {
		log_error("Failed to reset perf sampling!\n");
	}

	ret = ioctl(perf_event->perf_fd, PERF_EVENT_IOC_SET_FILTER, buffer);
	if (ret) {
		log_error("Failed apply event filter!\n");
	}

	ret = ioctl(perf_event->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret) {
		log_error("Failed to start perf sampling!\n");
	}

	return ret;
}

int perf_handle_sample(struct PerfEvent *perf_event, const unsigned char* header) {
	struct perf_sample_fix *body = (struct perf_sample_fix*)header;
	log_debug("Event: %s", perf_event->event_name);

	if (SAMPLE_CONFIG_FLAG & PERF_SAMPLE_TID & PERF_SAMPLE_CPU) {
		log_debug(" on PID %d, TID %d, CPU %d, RES %d\n", perf_event->event_name, body->pid, body->tid, body->cpu, body->res);
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

int perf_handle_lost_event(const unsigned char* header) {
	struct perf_lost_events *body = (struct perf_lost_events*)header;
	log_warn("Lost event on CPU %d!\n", body->sample_id.cpu);
	return 0;
}

int perf_event_process(struct PerfEvent *perf_event) {
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

int perf_event_clean(struct PerfEvent *perf_event) {
	int ret;
	ret = ioctl(perf_event->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
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

	ret = close(perf_event->perf_fd);
	if (ret) {
		log_error("Failed to close perf fd!\n");
	} else {
		perf_event->perf_fd = -1;
	}

	return ret;
}
