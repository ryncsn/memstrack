#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "memstrack.h"
#include "tracing.h"
#include "report.h"
#include "proc.h"

static void report_module_summary(void) {
	struct Module **modules;
	modules = collect_modules_sorted(0);

	for (int i = 0; i < module_map.size; ++i) {
		log_info(
				"Module %s using %.1lfMB (%d pages), peak allocation %.1lfMB (%d pages)\n",
				modules[i]->name,
				modules[i]->tracenode.record->pages_alloc * ((double)page_size) / 1024,
				modules[i]->tracenode.record->pages_alloc,
				modules[i]->tracenode.record->pages_alloc_peak * ((double)page_size) / 1024,
				modules[i]->tracenode.record->pages_alloc_peak
			);
	}

	free(modules);
}

static void report_module_top(void) {
	struct Module **modules;
	modules = collect_modules_sorted(0);

	for (int i = 0; i < module_map.size; ++i) {
		log_info("Top stack usage of module %s:\n", modules[i]->name);
		print_tracenode(&modules[i]->tracenode, 2, 1, 0);
	}

	free(modules);
}

static void report_task_summary (void) {
	long nr_pages_limit;
	struct Task **tasks;

	nr_pages_limit = page_alloc_counter - page_free_counter;
	nr_pages_limit = (nr_pages_limit * m_throttle + 99) / 100;

	tasks = collect_tasks_sorted(0);
	for (int i = 0; i < task_map.size; ++i) {
		log_info(
				"Task %s (%u) using %u pages, peak usage %u pages\n",
				tasks[i]->task_name, tasks[i]->pid,
				tasks[i]->tracenode.record->pages_alloc,
				tasks[i]->tracenode.record->pages_alloc_peak);
	}

	free(tasks);
};

static void report_task_top (void) {
	struct Task **tasks;
	long nr_pages_limit;

	nr_pages_limit = page_alloc_counter - page_free_counter;
	nr_pages_limit = (nr_pages_limit * m_throttle + 99) / 100;
	tasks = collect_tasks_sorted(0);

	for (int i = 0; i < task_map.size && nr_pages_limit > 0; i++) {
		print_task(tasks[i]);

		if (m_sort_alloc)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc;
		else if (m_sort_peak)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc_peak;
	}

	free(tasks);
};

static void report_task_top_json(void) {
	struct Task **tasks;
	long nr_pages_limit;

	nr_pages_limit = page_alloc_counter - page_free_counter;
	nr_pages_limit = (nr_pages_limit * m_throttle + 99) / 100;
	tasks = collect_tasks_sorted(0);

	log_info("[\n");
	for (int i = 0; i < task_map.size && nr_pages_limit > 0; i++) {
		print_task_json(tasks[i]);

		if (m_sort_alloc)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc;
		else if (m_sort_peak)
			nr_pages_limit -= tasks[i]->tracenode.record->pages_alloc_peak;

		if (i + 1 < task_map.size && nr_pages_limit)
			log_info(",\n");
		else
			log_info("\n");
	}
	log_info("]\n");
	free(tasks);
};

static void report_proc_slab_static(void) {
	print_slab_usage();
}

struct reporter_table_t  reporter_table[] = {
	{"module_summary", report_module_summary},
	{"module_top", report_module_top},
	{"task_summary", report_task_summary},
	{"task_top", report_task_top},
	{"task_top_json", report_task_top_json},
	{"proc_slab_static", report_proc_slab_static},
};

int report_table_size = sizeof(reporter_table) / sizeof(struct reporter_table_t);

void final_report(struct HashMap *task_map, int task_limit) {
	load_kallsyms();

	char *report_type;
	report_type = strtok(m_report, ",");

	do {
		for (int i = 0; i < report_table_size; ++i) {
			if (!strcmp(reporter_table[i].name, report_type)) {
				log_info("\n======== Report format %s: ========\n", report_type);
				reporter_table[i].report();
				log_info("======== Report format %s END ========\n", report_type);
			}
		}
		report_type = strtok(NULL, ",");
	} while (report_type);
}
