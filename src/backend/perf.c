/*
 * perf.c
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
#include <malloc.h>
#include <string.h>
#include <poll.h>

#include "../memstrack.h"
#include "perf-internal.h"

int perf_buf_size_per_cpu = 4 << 20;

int perf_event_ring_num;
struct PerfEventRing *perf_event_rings;
struct pollfd *perf_fds;

static void assign_cpu_no(int cpu_no, void *rings) {
	(*(struct PerfEventRing**)rings)->cpu = cpu_no;
	(*(struct PerfEventRing**)rings)++;
}

int perf_handling_init() {
	int ret;
	int cpu_num = perf_get_cpu_num();
	const struct perf_event_table_entry *entry;

	ret = perf_init(perf_buf_size_per_cpu);
	if (ret < 0) {
		return ret;
	}

	perf_event_ring_num = ret * perf_get_cpu_num();
	perf_event_rings = (struct PerfEventRing*)calloc(perf_event_ring_num, sizeof(struct PerfEventRing));

	for (int i = 0; i < perf_event_entry_number; i++){
		struct PerfEventRing *rings = perf_event_rings + (i * cpu_num);
		entry = perf_event_table + i;

		if (!entry->is_enabled() || !entry->event->valid)
			continue;

		for (int cpu = 0; cpu < cpu_num; cpu++) {
			rings[cpu].event = entry->event;
			rings[cpu].sample_handler = entry->handler;
		}

		for_each_online_cpu(assign_cpu_no, &rings);
	}

	for (int i = 0; i < perf_event_ring_num; i++) {
		ret = perf_ring_setup(perf_event_rings + i);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

int perf_apply_fds(struct pollfd *fds) {
	perf_fds = fds;
	for (int i = 0; i < perf_event_ring_num; i++) {
		perf_fds[i].fd = perf_event_rings[i].fd;
		perf_fds[i].events = POLLIN;
	}
	return 0;
}

int perf_handling_clean() {
	int i;
	for (i = 0; i < perf_event_ring_num; i++) {
		perf_ring_clean(perf_event_rings + i);
	}
	return 0;
}

int perf_handling_start() {
	int err = 0;
	for (int i = 0; i < perf_event_ring_num; i++) {
		err = perf_ring_start_sampling(perf_event_rings + i);
		if (err) {
			log_error("Failed starting perf event sampling: %s!\n", strerror(err));
		}
	}
	return err;
}

int perf_handling_process() {
	int err = 0, i;
	for (i = 0; i < perf_event_ring_num; i++) {
		err = perf_ring_process(perf_event_rings + i);
		if (err) {
			return err;
		}
	}
	return err;
}
