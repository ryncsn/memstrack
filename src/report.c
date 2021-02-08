/*
 * report.c
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memstrack.h"
#include "tracing.h"
#include "report.h"
#include "proc.h"

int report_default_throttle;

static void report_module_summary(struct reporter_fmt* fmt) {
	struct Module **modules;
	modules = collect_modules_sorted(0);

	for (int i = 0; i < module_map.size; ++i) {
		log_info(
				"Module %s using %.1lfMB (%ld pages), peak allocation %.1lfMB (%ld pages)\n",
				modules[i]->name,
				modules[i]->tracenode.record->pages_alloc * ((double)page_size) / 1024 / 1024,
				modules[i]->tracenode.record->pages_alloc,
				modules[i]->tracenode.record->pages_alloc_peak * ((double)page_size) / 1024 / 1024,
				modules[i]->tracenode.record->pages_alloc_peak
			);
	}

	free(modules);
}

static void report_module_top(struct reporter_fmt* fmt) {
	struct Module **modules;
	modules = collect_modules_sorted(0);

	for (int i = 0; i < module_map.size; ++i) {
		log_info("Top stack usage of module %s:\n", modules[i]->name);
		print_tracenode(&modules[i]->tracenode, 2, 2, 0);
	}

	free(modules);
}

static long overall_page_limit(int throttle) {
	long nr_pages_limit;

	nr_pages_limit = page_alloc_counter - page_free_counter;

	if (throttle > 0)
		nr_pages_limit = (nr_pages_limit * throttle + 99) / 100;

	return nr_pages_limit;
}

static void report_task_summary (struct reporter_fmt* fmt) {
	int task_num;
	long nr_pages_limit;
	struct Task **tasks;

	nr_pages_limit = overall_page_limit(fmt->throttle);
	tasks = collect_tasks_sorted(0, &task_num);
	for (int i = 0; i < task_num && nr_pages_limit > 0; ++i) {
		log_info(
				"Task %s (%ld) using %ld pages, peak usage %ld pages\n",
				tasks[i]->task_name, tasks[i]->pid,
				tasks[i]->tracenode.record->pages_alloc,
				tasks[i]->tracenode.record->pages_alloc_peak);
		nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc;
	}

	free(tasks);
};

static void report_task_top(struct reporter_fmt* fmt) {
	int task_num;
	long nr_pages_limit;
	struct Task **tasks;

	nr_pages_limit = overall_page_limit(fmt->throttle);
	tasks = collect_tasks_sorted(0, &task_num);

	for (int i = 0; i < task_num && nr_pages_limit > 0; i++) {
		print_task(tasks[i], fmt->top, fmt->throttle);
		nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc;
	}

	free(tasks);
};

static void report_task_top_json(struct reporter_fmt* fmt) {
	int task_num;
	long nr_pages_limit;
	struct Task **tasks;

	nr_pages_limit = overall_page_limit(fmt->throttle);
	tasks = collect_tasks_sorted(0, &task_num);

	log_info("[\n");
	for (int i = 0; i < task_num && nr_pages_limit > 0; i++) {
		print_task_json(tasks[i]);
		nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc_peak;

		if (i + 1 < task_num && nr_pages_limit)
			log_info(",\n");
		else
			log_info("\n");
	}
	log_info("]\n");
	free(tasks);
};

static void report_proc_slab_static(struct reporter_fmt* fmt) {
	print_slab_usage();
}

struct reporter_table_t reporter_table[] = {
	{"module_summary", report_module_summary},
	{"module_top", report_module_top},
	{"task_summary", report_task_summary},
	{"task_top", report_task_top},
	{"task_top_json", report_task_top_json},
	{"proc_slab_static", report_proc_slab_static},
};

int report_table_size = sizeof(reporter_table) / sizeof(struct reporter_table_t);

/* This func will write to fmt_tok */
static int parse_report_fmt_tok(char *fmt_tok,
		struct reporter_table_t **reporter, struct reporter_fmt *fmt) {
	char *report_type, *report_arg, *tmp;

	struct reporter_fmt parsed_fmt = { 0 };
	struct reporter_table_t *parsed_reporter = NULL;

	report_type = fmt_tok;
	strtok_r(report_type, ":", &tmp);
	report_arg = strtok_r(NULL, ":", &tmp);
	parsed_fmt.throttle = report_default_throttle;

	for (int i = 0;; ++i) {
		if (!strcmp(reporter_table[i].name, report_type)) {
			parsed_reporter = &reporter_table[i];
			break;
		}
	}

	if (!parsed_reporter) {
		log_error("Invalid report type: %s\n", report_type);
		return -1;
	}

	while (report_arg) {
		if (strcmp(report_arg, "sort_by_alloc") == 0) {
			parsed_fmt.sort_by = SORT_BY_ALLOC;
		} else if (strcmp(report_arg, "sort_by_peak") == 0) {
			parsed_fmt.sort_by = SORT_BY_PEAK;
		} else if (strncmp(report_arg, "throttle=", sizeof("throttle")) == 0) {
			char *end_p;
			parsed_fmt.throttle = strtol(report_arg + sizeof("throttle"), &end_p, 10);
			if (*end_p != '\0')
				goto err_arg;
		} else if (strncmp(report_arg, "top=", sizeof("top")) == 0) {
			char *end_p;
			parsed_fmt.top = strtol(report_arg + sizeof("top"), &end_p, 10);
			if (*end_p != '\0')
				goto err_arg;
		} else {
			goto err_arg;
		}
		report_arg = strtok_r(NULL, ":", &tmp);
	}

	if (fmt)
		memcpy(fmt, &parsed_fmt, sizeof(parsed_fmt));
	if (reporter)
		*reporter = parsed_reporter;

	return 0;

err_arg:
	log_error("Invalid report arg: %s\n", report_arg);
	return -1;
}

void do_report(const char *fmt_str) {
	char *report_fmt, *report_tok, *tmp;
	struct reporter_fmt parsed_fmt;
	struct reporter_table_t *parsed_reporter;

	report_fmt = strdup(fmt_str);
	report_tok = strtok_r(report_fmt, ",", &tmp);

	load_kallsyms();
	while (report_tok) {
		parse_report_fmt_tok(report_tok, &parsed_reporter, &parsed_fmt);

		log_info("\n======== Report format %s: ========\n", parsed_reporter->name);
		parsed_reporter->report(&parsed_fmt);
		log_info("======== Report format %s END ========\n", parsed_reporter->name);

		report_tok = strtok_r(NULL, ",", &tmp);
	}
	free(report_fmt);
}

/* {<type>[[:params]...],...} */
int check_report_fmt(const char *fmt_str) {
	int ret = 0;
	char *report_fmt, *report_tok, *tmp;

	report_fmt = strdup(fmt_str);
	report_tok = strtok_r(report_fmt, ",", &tmp);

	while (report_tok) {
		ret = parse_report_fmt_tok(report_tok, NULL, NULL);
		if (ret < 0)
			goto out;

		report_tok = strtok_r(NULL, ",", &tmp);
	};

out:
	free(report_fmt);
	return ret;
}
