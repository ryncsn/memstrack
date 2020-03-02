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
#include "memstrack.h"
#include "tracing.h"
#include "report.h"
#include "proc.h"
#include "tui.h"

int m_debug;
int m_perf = 1;
int m_ftrace = 0;
int m_throttle = 100;
int m_sort_alloc = 1;
int m_sort_peak = 0;
int m_notui;

char* m_report;
char* m_output_path;
FILE* m_output;

int m_page = 1;
int m_slab;
int m_loop = 1;

unsigned long trace_count;

unsigned int page_size;

char* m_perf_base;

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
	if (m_ftrace) {
		ftrace_handling_clean();
	}
	if (m_perf) {
		perf_handling_clean();
	}
	if (m_report) {
		final_report(&task_map, 0);
	}
	if (m_output != stdout) {
		fclose(m_output);
	}
}

void m_exit(int ret) {
	do_exit();
	exit(ret);
}

static void on_signal(int signal) {
	log_debug("Exiting on signal %d\n", signal);
	m_exit(0);
}

static struct option long_options[] =
{
	/* These options set a flag. */
	{"notui",		no_argument,		&m_notui,	1},
	{"debug",		no_argument,		&m_debug,	1},
	{"output",		required_argument,	0,		'o'},
	{"backend",		required_argument,	0,		'b'},
	{"throttle",		required_argument,	0,		't'},
	{"report",		required_argument,	0,		'r'},
	{"help",		no_argument,		0,		'?'},
	// {"human-readable",	no_argument,		0,		NULL},
	// {"trace-base",	required_argument,	0,		NULL},
	{0, 0, 0, 0}
};


static void display_usage() {
	log_info("Usage: memstrack [OPTION]... \n");
	log_info("    --notui		Only generate report.\n");
	log_info("    --output <file>\n");
	log_info("    			Generate trace report to given file instead of stdout.\n");
	log_info("    --backend {perf|ftrace}\n");
	log_info("    			Choose a backend for memory allocation tracing. Defaults to perf.\n");
	log_info("    			ftrace: poor performance but should always work.\n");
	log_info("    			perf: binary perf, may require CONFIG_FRAME_POINTER enabled for Kernel version <= 5.1.\n");
	log_info("    --throttle [PERCENTAGE]\n");
	log_info("    			Only print callsites consuming [PERCENTAGE] percent of total memory consumed.\n");
	log_info("    			expects a number between 0 to 100. Useful to filter minor allocations.\n");
	log_info("    --report {<type>,...}\n");
	log_info("    			Choose final report type, if multiple types are given, they are printed in given order.\n");
	log_info("    			Available report types: [ ");

	for (int i = 0; i < report_table_size; ++i) {
		log_info("\"%s\" ", reporter_table[i].name);
	}

	log_info("]\n");
	log_info("    --debug		Print more debug messages.\n");
	log_info("    --help 		Print this help message.\n");
	// log_info("    --throttle-peak	\n");
	// log_info("    --human-readable	Print sizes in a human reable way, eg bytes_alloc: 1048576 => 1M\n");
	// log_info("    --trace-base [DIR]	Use a different tracing mount path for ftrace.\n");
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

static void init_fds(void) {
	int extra_fd_num;
	int ret;

	if (m_notui) {
		log_warn("Tracing memory allocations, Press ^C to interrupt ...\n");
		extra_fd_num = 0;
	} else {
		extra_fd_num = 2;
	}

	if (m_perf) {
		ret = perf_handling_init();
		if (ret) {
			log_error("Failed initializing perf events\n");
			exit(ret);
		}

		m_pollfd_num = extra_fd_num + perf_count_fds();
	} else if (m_ftrace) {
		ret = ftrace_handling_init();
		if (ret) {
			log_error("Failed to open ftrace: %s!", strerror(ret));
			exit(ret);
		}

		m_pollfd_num = extra_fd_num + ftrace_count_fds();
	} else {
		log_error("BUG: No backend found\n");
		exit(1);
	}

	m_pollfds = malloc(m_pollfd_num * sizeof(struct pollfd));
	if (!m_pollfds) {
		log_error("Out of memory when try alloc fds\n");
	}

	if (m_perf) {
		perf_apply_fds(m_pollfds);
	} else if (m_ftrace) {
		ftrace_apply_fds(m_pollfds + extra_fd_num);
	}

	if (!m_notui)
		tui_apply_fds(m_pollfds);

	if (m_perf)
		perf_handling_start();
}

static void loop(void) {
	int ret;

	switch (ret = poll(m_pollfds, m_pollfd_num, 250)) {
		// Resizing the terminal causes poll() to return -1
		case -1:
		default:
			if (m_perf) {
				perf_handling_process();
			} else if (m_ftrace) {
				ftrace_handling_process();
			}

			if (!m_notui)
				tui_update();
	}
}

int main(int argc, char **argv) {
	tune_glibc();
	m_output = stdout;

	if (getuid() != 0) {
		log_error("This tool requires root permission to work.\n");
		exit(EPERM);
	}

	set_high_priority();

	while (1) {
		int opt;
		int option_index = 0;
		char *report_type;

		opt = getopt_long(argc, argv, "dho:b:t:r:?", long_options, &option_index);

		/* Detect the end of the options. */
		if (opt == -1)
			break;

		switch (opt)
		{
			case 0:
				// Flag setted, nothing to do
				break;
			case 'p':
				m_perf_base = (char*)calloc(sizeof(char), strlen(optarg) + 1);
				strcpy(m_perf_base, optarg);
				break;
			case 'r':
				m_report = strdup(optarg);
				report_type = strtok(m_report, ",");
				do {
					for (int i = 0;; ++i) {
						if (i == report_table_size) {
							log_error("Invalid report type: %s\n", report_type);
							m_exit(1);
						}

						if (!strcmp(reporter_table[i].name, report_type)) {
							break;
						}
					}
					report_type = strtok(NULL, ",");
				} while (report_type);

				/* Re-copy it, strtok will corrupt current one */
				free(m_report);
				m_report = strdup(optarg);

				break;
			case 'o':
				if (m_output_path) {
					free(m_output_path);
					m_output_path = NULL;
				}
				log_debug("Detailed report will be write to %s.\n", optarg);
				m_output_path = strdup(optarg);
				break;
			case 't':
				m_throttle = atoi(optarg);
				if (m_throttle < 0 || m_throttle > 100) {
					log_error("--throttle expects an integer between 0 - 100!\n");
					exit(1);
				}
				break;
			case 'b':
				if (!strcmp(optarg, "perf")) {
					m_perf = 1;
					m_ftrace = 0;
				} else if (!strcmp(optarg, "ftrace")) {
					m_perf = 0;
					m_ftrace = 1;
				} else {
					log_error("Unknown tracing backend '%s'.\n", optarg);
					exit(1);
				}
				break;
			case 's':
				if (strcmp(optarg, "peak")) {
					m_sort_peak = 1;
					m_sort_alloc = 0;
				} else if (strcmp(optarg, "alloc")) {
					m_sort_peak = 0;
					m_sort_alloc = 1;
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

	page_size = getpagesize();

	mem_tracing_init();

	signal(SIGINT, on_signal);

	init_fds();

	if (!m_notui)
		tui_init();

	while (m_loop) {
		trace_count ++;
		loop();
	}

	do_exit();

	return 0;
}
