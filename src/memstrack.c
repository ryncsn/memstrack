/*
 * memstrack.c
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
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <malloc.h>

#include <sys/resource.h>

#include "backend/perf.h"
#include "backend/ftrace.h"
#include "backend/page_owner.h"
#include "memstrack.h"
#include "tracing.h"
#include "report.h"
#include "proc.h"
#include "tui.h"

enum { BACKEND_PERF, BACKEND_FTRACE, BACKEND_PAGEOWNER } m_backend;

int m_debug;
int m_notui;

const char* m_report;
char* m_output_path;
FILE* m_output;

int m_slab;
int m_page = 1;
int m_loop = 1;
int m_buf_size = 4 << 20;

struct pollfd *m_pollfds;
int m_pollfd_num;

int m_log(int level, const char *__restrict fmt, ...){
	if (!m_debug && level <= LOG_LVL_DEBUG) {
		return 0;
	}

	int ret;
	va_list args;
	va_start (args, fmt);
	if (level == LOG_LVL_INFO) {
		ret = vfprintf(m_output, fmt, args);
	} else {
		ret = vfprintf(stderr, fmt, args);
	}
	va_end (args);
	return ret;
}

static void do_exit() {
	switch (m_backend) {
		case BACKEND_PERF:
			perf_handling_clean();
			break;
		case BACKEND_FTRACE:
			ftrace_handling_clean();
			break;
		default:
			break;
	}

	if (m_report) {
		do_report(m_report);
	}

	if (m_output != stdout) {
		fclose(m_output);
	}
}

void m_exit(int ret) {
	m_loop = 0;
	exit(ret);
}

static void on_signal(int signal) {
	m_loop = 0;
}

static void tune_glibc() {
	mallopt(M_TOP_PAD, 4096);
	mallopt(M_TRIM_THRESHOLD, 4096);
}

static void set_high_priority() {
	int which = PRIO_PROCESS;
	int priority = -20;
	int ret;
	id_t pid;

	pid = getpid();
	ret = setpriority(which, pid, priority);

	if (ret) {
		log_error("Failed to set high priority with %s.\n", strerror(ret));
	}
}

static void init(void) {
	int ui_fd_num;
	int ret;

	if (m_notui) {
		log_warn("Tracing memory allocations, Press ^C to interrupt ...\n");
		ui_fd_num = 0;
	} else {
		ui_fd_num = 2;
	}

	if (m_backend == BACKEND_PERF) {
		ret = perf_handling_init();
		if (ret) {
			log_error("Failed initializing perf events\n");
			exit(ret);
		}

		m_pollfd_num = ui_fd_num + perf_event_ring_num;
	} else if (m_backend == BACKEND_FTRACE) {
		ret = ftrace_handling_init();
		if (ret) {
			log_error("Failed to open ftrace: %s!", strerror(ret));
			exit(ret);
		}

		m_pollfd_num = ui_fd_num + ftrace_count_fds();
	} else if (m_backend == BACKEND_PAGEOWNER) {
		m_pollfd_num = ui_fd_num;
		page_owner_handling_init();
	} else {
		log_error("BUG: No backend found\n");
		exit(1);
	}

	m_pollfds = malloc(m_pollfd_num * sizeof(struct pollfd));
	if (!m_pollfds) {
		log_error("Out of memory when try alloc fds\n");
	}

	if (m_backend == BACKEND_PERF) {
		perf_apply_fds(m_pollfds + ui_fd_num);
	} else if (m_backend == BACKEND_FTRACE) {
		ftrace_apply_fds(m_pollfds + ui_fd_num);
	}

	if (!m_notui)
		tui_apply_fds(m_pollfds);
}

static void loop(void) {
	switch (poll(m_pollfds, m_pollfd_num, 250)) {
		// Resizing the terminal causes poll() to return -1
		// case -1:
		default:
			if (m_backend == BACKEND_PERF) {
				perf_handling_process();
			} else if (m_backend == BACKEND_FTRACE) {
				ftrace_handling_process();
			}
			if (!m_notui)
				tui_loop();
	}
}

static void display_usage() {
	log_info("Usage: memstrack [OPTION]... \n");
	log_info("    --notui		Only generate report.\n");
	log_info("    --output <file>\n");
	log_info("    			Generate trace report to given file instead of stdout.\n");
	log_info("    --backend {perf|ftrace|pageowner}\n");
	log_info("    			Choose a backend for memory allocation tracing. Defaults to perf.\n");
	log_info("    			ftrace: poor performance but should always work.\n");
	log_info("    			perf: binary perf, may require CONFIG_FRAME_POINTER enabled for Kernel version <= 5.1.\n");
	log_info("    --throttle <PERCENTAGE>\n");
	log_info("    			A global default throttle. When set, only callsites consuming [PERCENTAGE] will be shown in report.\n");
	log_info("    			Could be overridden by per reporter param.\n");

	log_info("    --report {<type>[[:params]...],...}\n");
	log_info("    			Choose final report type, if multiple types are given, they are printed in given order.\n");
	log_info("    			Params could be:\n");
	log_info("    				sort_by_alloc: Sort by memory usage\n");
	log_info("    				sort_by_peak:  Sort by peak memory usage\n");
	log_info("    				throttle=<PERCENT>: Only print top callsites that consumes <PERCENT> of memories\n");
	log_info("    				top=<NUM>: Only print top N callsites\n");
	log_info("    			Available report types: [ ");
	for (int i = 0; i < report_table_size; ++i) {
		log_info("\"%s\" ", reporter_table[i].name);
	}
	log_info("]\n");
	log_info("    --pageowner-file <file>\n");
	log_info("    			Only use with '--backend pageowner', will read from specified page owner log file instead of /sys/kernel/debug/page_owner.\n");
	log_info("    --buf-size <MB>\n");
	log_info("    			Buffer size for collecting memory allocation info, this is a per-CPU buffer size, and defaults to 4M per CPU, increase this value may help to reduce event lose rate.\n");
	log_info("    --debug		Print more debug messages.\n");
	log_info("    --help 		Print this help message.\n");
	// log_info("    --throttle-peak	\n");
	// log_info("    --human-readable	Print sizes in a human reable way, eg bytes_alloc: 1048576 => 1M\n");
	// log_info("    --trace-base [DIR]	Use a different tracing mount path for ftrace.\n");
}


int main(int argc, char **argv) {
	tune_glibc();
	m_output = stdout;

	if (getuid() != 0) {
		log_error("This tool requires root permission to work.\n");
		exit(EPERM);
	}

	set_high_priority();

	struct option long_options[] = {
		/* These options set a flag. */
		{"notui",		no_argument,		&m_notui,	1},
		{"debug",		no_argument,		&m_debug,	1},
		{"output",		required_argument,	0,		'o'},
		{"backend",		required_argument,	0,		'b'},
		{"throttle",            required_argument,      0,              't'},
		{"report",		required_argument,	0,		'r'},
		{"buf-size",		required_argument,	0,		's'},
		{"pageowner-file",	required_argument,	0,		'p'},
		{"help",		no_argument,		0,		'?'},
		// {"human-readable",	no_argument,		0,		'h'},
		{0, 0, 0, 0}
	};

	while (1) {
		int opt;
		int option_index = 0;

		opt = getopt_long(argc, argv, "dho:b:t:r:s:?", long_options, &option_index);

		/* Detect the end of the options. */
		if (opt == -1)
			break;

		switch (opt)
		{
			case 0:
				// Flag setted, nothing to do
				break;
			case 'r':
				if (check_report_fmt(optarg) < 0)
					m_exit(1);
				m_report = optarg;
				break;
			case 's':
				m_buf_size = atoi(optarg);
				if (m_buf_size < 0) {
					log_error("--buf-size expects an integer  0.\n");
					exit(1);
				}
				perf_buf_size_per_cpu = m_buf_size << 20;
				break;
			case 't':
				report_default_throttle = atoi(optarg);
				if (report_default_throttle < 0 || report_default_throttle > 100) {
					log_error("--throttle expects an integer between 0 - 100.\n");
					exit(1);
				}
				break;
			case 'p':
				page_owner_set_filepath(strdup(optarg));
				break;
			case 'o':
				if (m_output_path) {
					free(m_output_path);
					m_output_path = NULL;
				}
				log_debug("Detailed report will be write to %s.\n", optarg);
				m_output_path = strdup(optarg);
				break;
			case 'b':
				if (!strcmp(optarg, "perf")) {
					m_backend = BACKEND_PERF;
				} else if (!strcmp(optarg, "ftrace")) {
					m_backend = BACKEND_FTRACE;
				} else if (!strcmp(optarg, "pageowner")) {
					m_backend = BACKEND_PAGEOWNER;
				} else {
					log_error("Unknown tracing backend '%s'.\n", optarg);
					exit(1);
				}
				break;
			case '?':
				display_usage();
				exit(0);
			default:
				display_usage();
				exit(1);
		}
	}

	if (m_output_path) {
		m_output = fopen(m_output_path, "w");
		if (!m_output) {
			log_error("Failed to open file '%s' for writing.\n", m_output_path);
		} else {
			free(m_output_path);
		}
	}

	if (mem_tracing_init()) {
		exit(1);
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	init();

	if (!m_notui)
		tui_init();

	if (m_backend == BACKEND_PERF)
		perf_handling_start();

	while (m_loop) {
		loop();
	}

	do_exit();

	return 0;
}
