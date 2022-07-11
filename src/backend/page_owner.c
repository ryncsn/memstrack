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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include <malloc.h>
#include <errno.h>

#include "../memstrack.h"
#include "../tracing.h"

#define PAGE_OWNER_FILE "/sys/kernel/debug/page_owner"
#define PAGE_ALLOC_HEADER "Page allocated via order "
#define PFN_HEADER "PFN "
#define MAX_LINE 1024

static char *page_owner_file;

static char *memcg_info[] = {
	"Slab cache page",
	"Charged ",
};

static int is_memcg_info(char *str)
{
	for (int i = 0;
	     i < sizeof(memcg_info) / sizeof(__typeof__(memcg_info[0]));
	     i++) {
		if (!strncmp(str, memcg_info[i], strlen(memcg_info[i]))) {
			return true;
		}
	}
	return false;
}

static struct Tracenode* __process_stacktrace(
		struct Tracenode *tn, struct PageEvent *pe, char *line, FILE *file)
{
	struct Tracenode *tp = NULL;
	char *callsite;
	int callsite_len;
	unsigned long len;

retry:
	if (!fgets(line, MAX_LINE, file)) {
		log_error("Page owner file ended unexpectly before stacktrace.\n");
		return NULL;
	}

	len = strlen(line);
	if (len == 0) {
		log_error("Page owner stacktrace ended unexpectly.\n");
		return NULL;
	}

	if (is_memcg_info(line))
		goto retry;

	/* Empty line, end of a stacktrace */
	if (line[0] == '\n' || line[0] == '\r')
		return tn;

	// Skip the leading space by + 1
	if (line[0] != ' ') {
		log_error("Page owner stacktrace malformed.\n");
		return NULL;
	}
	line++;

	callsite_len = strlen(line) - 1;
	while (callsite_len > 0 && isspace(line[callsite_len]))
		callsite_len--;

	if (callsite_len < 1) {
		log_error("Page owner stacktrace contains empty line.\n");
		return NULL;
	}
	callsite = strndup(line, callsite_len);

	// Process next traceline
	tp = __process_stacktrace(tn, pe, line, file);
	if (tp == NULL) {
		free(callsite);
		return NULL;
	}

	tp = get_or_new_child_tracenode(tp, callsite);
	update_tracenode_record(tp, pe);

	return tp;
}

static int page_owner_handle_header(struct PageEvent *event, char *line, FILE *file) {
	char *arg, *end;
	int pfn;
	unsigned long len;

	len = strlen(line);
	if (len > sizeof(PAGE_ALLOC_HEADER) - 1)
		len = sizeof(PAGE_ALLOC_HEADER) - 1;

	if (strncmp(line, PAGE_ALLOC_HEADER, len) == 0) {
		arg = line + len;
		strtol(arg, &end, 10);
		if (end == arg || *end != ',') {
			log_error("Failed to parse page order.");
			return -1;
		}
	} else {
		log_error("Failed to read page allocation info.");
		return -1;
	}

	if (!fgets(line, MAX_LINE, file)) {
		log_error("Page owner file ended unexpectly.");
		return -1;
	}

	len = strlen(line);
	if (len > sizeof(PFN_HEADER) - 1)
		len = sizeof(PFN_HEADER) - 1;

	if (strncmp(line, PFN_HEADER, len) == 0) {
		arg = line + len;
		pfn = strtol(arg, &end, 10);
		if (end == arg || *end != ' ') {
			log_error("Failed to parse page pfn.");
			return -1;
		}
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
	struct PageEvent pe = {0};
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
	int ret;

	fpath = page_owner_file ? page_owner_file : PAGE_OWNER_FILE;
	log_debug("Using %s as page owner log file\n", fpath);

	file = fopen(fpath, "r");
	if (!file) {
		log_error("Failed to open %s with %s\n", fpath, strerror(errno));
		return -1;
	}

	store_symbol_instead();
	ret = page_owner_process_all(file);

	fclose(file);
	return ret;
}

void page_owner_set_filepath(char *path) {
	page_owner_file = path;
}
