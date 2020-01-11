#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <malloc.h>

#include <sys/resource.h>

#include "perf-handler.h"
#include "ftrace-handler.h"
#include "memory-tracer.h"
#include "tracing.h"
#include "proc.h"

int memtrac_debug;
int memtrac_human;
int memtrac_perf;
int memtrac_ftrace;
int memtrac_json;
int memtrac_slab;
int memtrac_page;
int memtrac_show_misc;
int memtrac_throttle = 100;
int memtrac_summary;
int memtrac_sort_alloc = 1;
int memtrac_sort_peak = 0;

unsigned int page_size;

char* memtrac_perf_base;

int memtrac_log (int level, const char *__restrict fmt, ...){
	if (!memtrac_debug && level <= LOG_LVL_DEBUG) {
		return 0;
	}
	int ret;
	va_list args;
	va_start (args, fmt);
	if (level >= LOG_LVL_WARN) {
		ret = vfprintf(stderr, fmt, args);
	} else {
		ret = vfprintf(stdout, fmt, args);
	}
	va_end (args);
	return ret;
}

static void do_exit() {
	if (memtrac_ftrace) {
		ftrace_handling_clean();
	}
	if (memtrac_perf) {
		perf_handling_clean();
	}
	final_report(&TaskMap, 0);
	exit(0);
}

static void on_signal(int signal) {
	log_debug("Exiting on signal %d\n", signal);
	do_exit();
}

static void do_process_perf() {
	perf_handling_start();
	while (1) {
		perf_handling_process();
	}
}

static void do_process_ftrace() {
	while (1) {
		ftrace_handling_process();
	}
}

static struct option long_options[] =
{
	/* These options set a flag. */
	{"ftrace",		no_argument,	&memtrac_ftrace,	1},
	{"perf",		no_argument,	&memtrac_perf,		1},
	{"slab",		no_argument,	&memtrac_slab,		1},
	{"page",		no_argument,	&memtrac_page,		1},
	{"json",		no_argument,	&memtrac_json,		1},
	{"show-misc",		no_argument,	&memtrac_show_misc,	1},
	{"summary",		no_argument,	&memtrac_summary,	1},
	{"debug",		no_argument,		0,		'd'},
	// {"human-readable",	no_argument,		0,		'h'},
	// {"trace-base",	required_argument,	0,		'b'},
	{"throttle",		required_argument,	0,		't'},
	{"sort-by",		required_argument,	0,		's'},
	{"help",		no_argument,		0,		'?'},
	{0, 0, 0, 0}
};


static void display_usage() {
	log_info("Usage: memory-tracer [OPTION]... \n");
	log_info("    --debug		Print debug messages. \n");
	log_info("    --ftrace		Use ftrace for tracing, poor performance but should always work. \n");
	log_info("    --perf		Use binary perf for tracing, may require CONFIG_FRAME_POINTER enabled on older kernel (before 5.1). \n");
	log_info("    --page		Collect page usage statistic. \n");
	log_info("    --slab		Collect slab cache usage statistic. \n");
	// log_info("    --human-readable	Print sizes in a human reable way, eg bytes_alloc: 1048576 => 1M \n");
	log_info("    --json		Format result as json. \n");
	// log_info("    --trace-base [DIR]	Use a different tracing mount path. \n");
	log_info("    --show-misc	Generate a current memory usage summary report on start. \n");
	log_info("    --throttle [PERCENTAGE] \n");
	log_info("    			Only print callsites consuming [PERCENTAGE] percent of total memory consumed. \n");
	log_info("    			expects a number between 0 to 100. Useful to filter minor noises. \n");
	log_info("    --sort-by {peak|alloc} \n");
	log_info("    			How should the stack be sorted, by the peak usage or allocation statuc on tracer exit. \n");
	log_info("    			Defaults to peak. \n");
	log_info("    --summary \n");
	log_info("    			Generate a summary instead of detailed stack info. \n");
	log_info("    --help 		Print this message. \n");
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


int main(int argc, char **argv) {
	tune_glibc();
	page_size = getpagesize();

	mem_tracing_init();

	while (1) {
		int opt;
		int option_index = 0;

		opt = getopt_long(argc, argv, "db:h", long_options, &option_index);

		/* Detect the end of the options. */
		if (opt == -1)
			break;

		switch (opt)
		{
			case 0:
				// Flag setted, nothing to do
				break;
			case 'd':
				memtrac_debug = 1;
				break;
			case 'h':
				memtrac_human = 1;
				break;
			case 'b':
				memtrac_perf_base = (char*)calloc(sizeof(char), strlen(optarg) + 1);
				strcpy(memtrac_perf_base, optarg);
				break;
			case 't':
				memtrac_throttle = atoi(optarg);
				if (memtrac_throttle < 0 || memtrac_throttle > 100) {
					log_error("--throttle expects an integer between 0 - 100!\n");
					exit(1);
				}
				break;
			case 's':
				if (strcmp(optarg, "peak")) {
					memtrac_sort_peak = 1;
					memtrac_sort_alloc = 0;
				} else if (strcmp(optarg, "alloc")) {
					memtrac_sort_peak = 0;
					memtrac_sort_alloc = 1;
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

	if (memtrac_show_misc) {
		print_slab_usage();
	}

	if (memtrac_perf && memtrac_ftrace) {
		log_error("Can't have --ftrace and --perf set together!\n");
		exit(EINVAL);
	}

	if (!memtrac_perf && !memtrac_ftrace) {
		memtrac_perf = 1;  // Use perf by default
	}

	if (!memtrac_page && !memtrac_slab) {
		log_error("At least one of --page and --slab is required.\n");
		exit(EINVAL);
	}

	if (getuid() != 0) {
		log_error("This tool requires root permission to work.\n");
		exit(EPERM);
	}

	int err;
	if (memtrac_perf) {
		err = perf_handling_init();
		if (err) {
			log_error("Failed initializing perf event buffer: %s!", strerror(err));
			exit(err);
		}
		signal(SIGINT, on_signal);
		do_process_perf();
	} else if (memtrac_ftrace) {
		err = ftrace_handling_init();
		if (err) {
			log_error("Failed to open ftrace: %s!", strerror(err));
			exit(err);
		}
		signal(SIGINT, on_signal);
		do_process_ftrace();
	}
	do_exit();
}
