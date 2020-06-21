/*
 * perf-internal.h
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

#include <linux/perf_event.h>

struct PerfEventField {
	char *name;
	char *type;

	short size;
	short offset;
	short is_signed;
	short checked;
};

struct PerfEvent {
	char *event_class;
	char *name;
	int id;

	unsigned long sample_type;
	unsigned int buf_size;
	short fileds_num;

	struct PerfEventField fields[];
};

typedef int (*SampleHandler) (const unsigned char*);

struct PerfEventRing {
	int cpu;
	int fd;

	struct PerfEvent *event;

	SampleHandler sample_handler;

	void *mmap;
	unsigned char *data;
	unsigned long long mmap_size;
	unsigned long long data_size;
	unsigned long long index;
	unsigned long long counter;

	struct perf_event_mmap_page *meta;
};

struct perf_event_table_entry {
	struct PerfEvent *event;
	SampleHandler handler;
	int (*is_enabled)(void);
};

extern const struct perf_event_table_entry perf_event_table[];

extern const int perf_event_entry_number;

int perf_load_events(void);
int perf_ring_setup(struct PerfEventRing *ring);
int perf_ring_start_sampling(struct PerfEventRing *ring);
int perf_ring_process(struct PerfEventRing *ring);
int perf_ring_clean(struct PerfEventRing *ring);

int perf_get_cpu_num(void);
int perf_do_load_event_info(struct PerfEvent *entry);

int sys_perf_event_open(struct perf_event_attr *attr,
		int pid, int cpu, int group_fd,
		unsigned long flags);

int for_each_online_cpu(void (*fn)(int cpu_no, void *blob), void *blob);
