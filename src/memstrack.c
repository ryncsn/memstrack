#define _GNU_SOURCE
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

// For TUI support
#include <ncurses.h>

#include "perf-handler.h"
#include "ftrace-handler.h"
#include "memstrack.h"
#include "tracing.h"
#include "proc.h"

int m_debug;
int m_human;
int m_perf = 1;
int m_ftrace;
int m_json;
int m_show_misc;
int m_throttle = 100;
int m_summary;
int m_sort_alloc = 1;
int m_sort_peak = 0;
int m_notui;

char* m_output_path;
FILE* m_output;

int m_page = 1;
int m_slab;

unsigned long trace_count;

unsigned int page_size;

char* m_perf_base;

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
	final_report(&TaskMap, 0);
	if (m_output != stdout) {
		fclose(m_output);
	}
	exit(0);
}

static void on_signal(int signal) {
	log_debug("Exiting on signal %d\n", signal);
	do_exit();
}

static struct option long_options[] =
{
	/* These options set a flag. */
	{"notui",		no_argument,		&m_notui,	1},
	{"json",		no_argument,		&m_json,	1},
	{"summary",		no_argument,		&m_summary,	1},
	{"show-misc",		no_argument,		&m_show_misc,	1},
	{"debug",		no_argument,		0,		'd'},
	{"output",		required_argument,	0,		'o'},
	{"backend",		required_argument,	0,		'b'},
	{"throttle",		required_argument,	0,		't'},
	{"sort-by",		required_argument,	0,		's'},
	{"help",		no_argument,		0,		'?'},
	// {"human-readable",	no_argument,		0,		NULL},
	// {"trace-base",	required_argument,	0,		NULL},
	{0, 0, 0, 0}
};


static void display_usage() {
	log_info("Usage: memstrack [OPTION]... \n");
	log_info("    --notui		Only generate report.\n");
	log_info("    --output <file>	Generate trace report to given file instead of stdout.\n");
	log_info("    --backend {perf|ftrace}\n");
	log_info("    			Choose a backend for memory allocation tracing. Defaults to perf.\n");
	log_info("    			ftrace: poor performance but should always work.\n");
	log_info("    			perf: binary perf, may require CONFIG_FRAME_POINTER enabled for Kernel version <= 5.1.\n");
	log_info("    --throttle [PERCENTAGE]\n");
	log_info("    			Only print callsites consuming [PERCENTAGE] percent of total memory consumed.\n");
	log_info("    			expects a number between 0 to 100. Useful to filter minor noises.\n");
	log_info("    --sort-by {peak|alloc} \n");
	log_info("    			How should the stack be sorted on start, by the peak usage or final usage.\n");
	log_info("    			Defaults to 'peak'.\n");
	log_info("    --json		Format report result as json.\n");
	log_info("    --summary 	Generate a summary report instead of detailed stack info.\n");
	log_info("    --show-misc	Generate a current memory usage summary report on start.\n");
	log_info("    --debug		Print more debug messages.\n");
	log_info("    --help 		Print this help message.\n");
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


static void loop_tracing(void) {
	int err;
	log_warn("Tracing memory allocations, Press ^C to interrupt ...\n");

	if (m_perf) {
		err = perf_handling_init();
		if (err) {
			log_error("Failed initializing perf event buffer: %s!", strerror(err));
			exit(err);
		}
		perf_handling_start();
		while (1) {
			perf_handling_process();
		}

	} else if (m_ftrace) {
		err = ftrace_handling_init();
		if (err) {
			log_error("Failed to open ftrace: %s!", strerror(err));
			exit(err);
		}
		while (1) {
			ftrace_handling_process();
		}
	}
}

#define MAX_TASK_VIEW 64
#define MAX_CALLSITE_VIEW 64
#define MISC_PAD 4

struct callsite_view_node {
	struct Callsite* callsite;
	struct callsite_view_node *callsite_head, *callsite_tail;
	bool highlight;
	int indent;
	struct callsite_view* next;
};

struct task_view_node {
	struct Task* task;
	struct callsite_view_node* callsite_head, callsite_tail;
} *task_view_head, *task_view_tail;

// TODO: Do this in another thread to avoid it blocking the tracing worker
static struct TraceNode generate_top_stacktrace(struct TraceNode* tn) {
	int total_count = LINES - MISC_PAD;

	for (int i = 0; i < total_count; ++i) {

	}
}

static struct TraceNode collect_top_task(int topn) {
	struct Task **tasks = NULL;
	struct HashNode *node = NULL;

	tasks = malloc(topn * sizeof(struct Task*));

	for (int i = 0, j = 0; i < HASH_BUCKET; i++) {
		if (TaskMap.buckets[i] != NULL) {
			node = TaskMap.buckets[i];
			while (node) {
				tasks[j] = container_of(node, struct Task, node);
				update_tracenode(to_tracenode(tasks[j]));
				node = node->next;
				j++;
			}
		}
	}

	qsort((void*)tasks, total_task_num, sizeof(struct Task*), comp_task_mem);
	return tasks;
}

int selected_line = 0;

static void extend_selected() {
}

static void loop_tui(void) {
	struct pollfd *fds;
	char mesg[] = "Last input: %c";
	int ch = ' ';
	int fd_num;
	int win_startx, win_starty, win_width, win_height;
	int err;
	WINDOW *trace_win;

	load_kallsyms();
	if (m_perf) {
		err = perf_handling_init();
		if (err) {
			log_error("Failed initializing perf event buffer: %s!", strerror(err));
			exit(err);
		}
		fd_num = 1 + perf_fd_num;
		fds = malloc(fd_num * sizeof(struct pollfd));

		fds[0].fd = STDIN_FILENO;
		fds[0].events = POLLIN;

		for (int i = 1; i < fd_num; i++) {
			fds[i].fd = perf_fds[i - 1].fd;
			fds[i].events = perf_fds[i - 1].events;;
		}
	} else {
		log_error("Not implemented\n");
		return;
	}

	initscr();
	keypad(stdscr, TRUE);
	timeout(-1);
	curs_set(0);
	noecho();
	raw();

	win_height = LINES - MISC_PAD; // 4 line above for info
	win_width = COLS;
	win_starty = MISC_PAD;
	win_startx = 0;
	trace_win = newwin(win_height, win_width, win_starty, win_startx);
	box(trace_win, 0, 0);
	wrefresh(trace_win);
	refresh();

	// TODO: ftrace
	perf_handling_start();

	do {
		switch(poll(fds, fd_num, 250))
		{
			// resizing the terminal causes poll() to return -1 (error)
			case -1:
				refresh();
				break;
			default:
				if (fds[0].revents & POLLIN) {
					// On user input
					ch = getch();
					if (ch == 'q') {
						endwin();
						return;
					}

					if (ch == 'r') {
						load_kallsyms();
					}

					box(trace_win, 0, 0);
					wrefresh(trace_win);
					mvprintw(0, 0,  "'q' to quit, 'r' to reload symbols\n");
					mvprintw(1, 0, "This screen has %d rows and %d columns, TC: %lu\n", LINES, COLS, trace_count);
					refresh();
				} else {
					perf_handling_process();
				}
		}
	} while(1);
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

		opt = getopt_long(argc, argv, "dhp:o:t:b:s:h", long_options, &option_index);

		/* Detect the end of the options. */
		if (opt == -1)
			break;

		switch (opt)
		{
			case 0:
				// Flag setted, nothing to do
				break;
			case 'd':
				m_debug = 1;
				break;
			case 'h':
				m_human = 1;
				break;
			case 'p':
				m_perf_base = (char*)calloc(sizeof(char), strlen(optarg) + 1);
				strcpy(m_perf_base, optarg);
				break;
			case 'o':
				if (m_output_path) {
					free(m_output_path);
					m_output_path = NULL;
				}
				log_error("Opening %s!\n", optarg);
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
				if (strcmp(optarg, "perf")) {
					m_perf = 1;
					m_ftrace = 0;
				} else if (strcmp(optarg, "ftrace")) {
					m_perf = 0;
					m_ftrace = 1;
				} else {
					log_error("Unknown tracing backend '%s'.\n", optarg);
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

	if (m_show_misc) {
		print_slab_usage();
	}

	signal(SIGINT, on_signal);

	if (m_notui)
		loop_tracing();
	else
		loop_tui();

	do_exit();
}
