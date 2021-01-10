/*
 * page_owner.c
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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <malloc.h>

#include "../memstrack.h"
#include "../tracing.h"

#define PAGE_OWNER_FILE "/sys/kernel/debug/page_owner"
#define PAGE_ALLOC_HEADER "Page allocated via order "
#define MAX_LINE 1024

static char *page_owner_file;

static struct Tracenode* __process_stacktrace(
		struct Tracenode *tn, struct PageEvent *pe, char *line, FILE *file)
{
	struct Tracenode *tp = NULL;
	char *callsite;
	int callsite_len;

	if (!fgets(line, MAX_LINE, file)) {
		log_error("Page owner file ended unexpectly before stacktrace.\n");
		return NULL;
	}

	/* \n, or \n\r just in case */
	if (strlen(line) <= 2)
		return tn;

	// Skip the leading space by + 1
	callsite = strdup(line + 1);
	callsite_len = strlen(callsite);
	callsite[callsite_len - 1] = '\0';

	// Process next traceline
	tp = __process_stacktrace(tn, pe, line, file);
	tp = get_or_new_child_tracenode(tp, callsite);
	update_tracenode_record(tp, pe);

	return tp;
}

static int page_owner_handle_header(struct PageEvent *event, char *line, FILE *file) {
	char *page_arg;
	int order, pfn;

	if (strncmp(line, PAGE_ALLOC_HEADER, sizeof(PAGE_ALLOC_HEADER) - 1) == 0) {
		page_arg = line + sizeof(PAGE_ALLOC_HEADER) - 1;
		sscanf(page_arg, "%d", &order);
	} else {
		log_error("Failed to read page allocation info.");
		return -1;
	}

	if (!fgets(line, MAX_LINE, file)) {
		log_error("Page owner file ended unexpectly.");
		return -1;
	}

	if (strncmp(line, "PFN ", sizeof("PFN ") - 1) == 0) {
		page_arg = line + sizeof("PFN ") - 1;
		sscanf(page_arg, "%d", &pfn);
	} else {
		log_error("Failed to read page pfn info.");
		return -1;
	}

	event->pages_alloc = 1;
	event->pfn = pfn;

	return 0;
}

static int page_owner_process_all(FILE *file) {
	int ret;
	struct PageEvent pe;
	struct Task *task;
	char line[MAX_LINE];

	task = get_or_new_task_with_name(0, "<early-init>");
	log_debug("Processing page owner log file... ");
	while (fgets(line, MAX_LINE, file)) {
		ret = page_owner_handle_header(&pe, line, file);
		if (ret)
			return ret;

		__process_stacktrace(to_tracenode(task), &pe, line, file);
	}
	log_debug("Done.\n");

	return 0;
}

int page_owner_handling_init() {
	char *fpath;
	FILE *file;

	fpath = page_owner_file ? page_owner_file : PAGE_OWNER_FILE;
	log_debug("Using %s as page owner log file\n", fpath);

	file = fopen(fpath, "r");
	if (!file) {
		log_error("Failed to open %s\n", fpath);
		return -1;
	}

	store_symbol_instead();
	return page_owner_process_all(file);
}

void page_owner_set_filepath(char *path) {
	page_owner_file = path;
}
