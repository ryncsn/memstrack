#define _GNU_SOURCE        /* See feature_test_macros(7) */
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/sysinfo.h>
#include <linux/perf_event.h>

#include "perf.h"

#define PERF_EVENTS_PATH "/sys/kernel/debug/tracing/events"

static inline int sys_perf_event_open(struct perf_event_attr *attr,
                      int pid, int cpu, int group_fd,
                      unsigned long flags)
{
	printf("CPU: %d ID: %lld\n", cpu, attr->config);
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

	strncpy(event_buffer, event, 1024);

	event_group = strtok(event_buffer, ":");
	event_name = strtok(NULL, ":");
	sprintf(path_buffer, "%s/%s/%s/id", PERF_EVENTS_PATH, event_group, event_name);

	FILE *id_file = fopen(path_buffer, "r");
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
	attr.sample_period = 32;
	attr.sample_type = SAMPLE_CONFIG_FLAG;

	attr.disabled = 1;
	// attr.exclude_callchain_user = 1;
	attr.config = perf_event->event_id;
	attr.precise_ip = 2;

	mmap_size = (CPU_BUFSIZE + 1) * getpagesize();

	attr.wakeup_watermark = mmap_size / 4;
	if (attr.wakeup_watermark < (__u32)getpagesize()) {
		fprintf(stderr, "perf ring buffer too small!\n");
	}
	attr.watermark = 1;

	perf_fd = sys_perf_event_open(&attr, -1, perf_event->cpu, -1, 0);

	if (perf_fd <= 0) {
		fprintf(stderr, "Error calling perf_event_open: %s\n", strerror(errno));
		return errno;
	}

	fcntl(perf_fd, F_SETFL, O_NONBLOCK);

	// Extra one page for metadata
	void *perf_mmap = mmap(NULL,
		       	mmap_size ,
			PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);

	if (perf_mmap == MAP_FAILED) {
		fprintf(stderr, "Failed mmaping perf ring buffer: %s\n", strerror(errno));
		return errno;
	}

	perf_event->perf_fd = perf_fd;
	perf_event->mmap_size = mmap_size;
	perf_event->data_size = mmap_size - getpagesize();
	perf_event->meta = (struct perf_event_mmap_page *)perf_mmap;
	perf_event->data = (unsigned char *)perf_mmap + getpagesize();
	perf_event->index = 0;

	return 0;
}

int perf_event_start_sampling(struct PerfEvent *perf_event) {
	char buffer[1024];
	sprintf(buffer, "common_pid!=%d", getpid());

	fprintf(stderr, "FD is %d!\n", perf_event->perf_fd);
	int ret;
	ret = ioctl(perf_event->perf_fd, PERF_EVENT_IOC_RESET, 0);
	if (ret) {
		fprintf(stderr, "Failed to reset perf sampling!\n");
	}

	ret = ioctl(perf_event->perf_fd, PERF_EVENT_IOC_SET_FILTER, buffer);
	if (ret) {
		fprintf(stderr, "Failed apply event filter!\n");
	}

	ret = ioctl(perf_event->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret) {
		fprintf(stderr, "Failed to start perf sampling!\n");
	}

	return ret;
}

int perf_handle_sample(struct PerfEvent *perf_event, const unsigned char* header) {
	struct perf_sample_fix *body = (struct perf_sample_fix*)header;
	fprintf(stderr, "DEBUG: Event: %s\n", perf_event->event_name);

	if (SAMPLE_CONFIG_FLAG & PERF_SAMPLE_TID & PERF_SAMPLE_CPU) {
		fprintf(stderr, "DEBUG: %s on PID %d, TID %d, CPU %d, RES %d\n", perf_event->event_name, body->pid, body->tid, body->cpu, body->res);
	}

	header += sizeof(*body);

	if (SAMPLE_CONFIG_FLAG & PERF_SAMPLE_CALLCHAIN) {
		struct perf_sample_callchain *callchain = (struct perf_sample_callchain*)header;
		fprintf(stderr, "Stack size %lu\n", callchain->nr);
		header += sizeof(callchain->nr);
		for (int i = 0; i < (int)callchain->nr; i++) {
			fprintf(stderr, "IP %lx\n", *((&callchain->ips) + i));
			header += sizeof(callchain->ips);
		}
	}

	if (SAMPLE_CONFIG_FLAG & PERF_SAMPLE_RAW) {
		struct perf_sample_raw *raw = (struct perf_sample_raw*)header;
		fprintf(stderr, "Raw size %u\n", raw->size);

		unsigned char *raw_data = (unsigned char*)(&raw->data);
		for (int i = 0; i < (int)raw->size; ++i) {
			fprintf(stderr, "Raw sec %d: 0x%x\n", i, raw_data[i]);
		}
	}

	return 0;
}

int perf_handle_lost_event(const unsigned char* header) {
	struct perf_lost_events *body = (struct perf_lost_events*)header;
	fprintf(stderr, "Lost event on CPU %d!\n", body->sample_id.cpu);
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
				fprintf(stderr, "DEBUG: Unexpected Event %x!\n", header->type);
				break;
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
		fprintf(stderr, "Failed to stop perf sampling!\n");
	}

	ret = munmap(perf_event->mmap, CPU_BUFSIZE);
	if (ret) {
		fprintf(stderr, "Failed to stop perf sampling!\n");
	} else {
		perf_event->mmap = NULL;
		perf_event->data = NULL;
		perf_event->meta = NULL;
	}

	ret = close(perf_event->perf_fd);
	if (ret) {
		fprintf(stderr, "Failed to stop perf sampling!\n");
	} else {
		perf_event->perf_fd = -1;
	}

	return ret;
}
