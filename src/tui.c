#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <poll.h>
#include <ncurses.h>

#include <sys/timerfd.h>
#include <sys/resource.h>

#include "memstrack.h"
#include "tracing.h"

#define MAX_TASK_VIEW 64
#define MAX_CALLSITE_VIEW 64
#define MISC_PAD 4
// Show 300 lines
#define MAX_VIEW 300
#define UI_FD_NUMS 2

struct TracenodeView {
	bool extended;
};

static struct pollfd *ui_fds;

static WINDOW *trace_win;

static int highline, shiftrol, task_count;

static struct Task **sorted_tasks;
static void update_top_tasks() {
	if (sorted_tasks)
		free(sorted_tasks);

	// TODO: No need to free / alloc every time
	sorted_tasks = collect_tasks_sorted(&TaskMap, &task_count, 1);

	for (int i = 0; i < task_count; ++i) {
		if (!to_tracenode(sorted_tasks[i])->record->blob)
			to_tracenode(sorted_tasks[i])->record->blob = calloc(1, sizeof(struct TracenodeView));
	}
};

int selected_line = 0;

static void trace_refresh_tui(WINDOW *win) {
	struct Task* task;
	struct Tracenode** nodes;
	struct TracenodeView *view;
	int start = MISC_PAD + 1;
	int linelimit = LINES - MISC_PAD - 3;
	int line_n, task_n, count;
	char linebuffer[1024];

	line_n = 0, task_n = 0;
	update_top_tasks();

	for (; task_n < task_count; ++task_n) {
		task = sorted_tasks[task_n];
		view = to_tracenode(task)->record->blob;
		sprintf(linebuffer, "%5ld | %10ld | %s\n", task->pid, task->tracenode.record->pages_alloc, task->task_name);
		linebuffer[COLS - 2] = '\0';
		mvprintw(start + line_n++, 1,  "%s", linebuffer);

		if (line_n > linelimit)
			return;

		if (view->extended) {
			nodes = collect_tracenodes_sorted(to_tracenode(task)->children, &count, 1);
			for (int i = 0; i < count; ++i) {
				if (!nodes[i]->record->blob)
					nodes[i]->record->blob = calloc(1, sizeof(struct TracenodeView));
				mvprintw(start + line_n++, 1,  "%lx\n", nodes[i]->addr);
				if (line_n > linelimit)
					return;
			}
		}
	}
}

static int gen_timerfd(unsigned int period)
{
	int fd;
	unsigned int ns;
	unsigned int sec;
	struct itimerspec itval = {0};

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		log_error("Failed creating timer");
		return -1;
	}

	/* Make the timer periodic */
	sec = period / 1000000;
	ns = (period - (sec * 1000000)) * 1000;
	itval.it_interval.tv_sec = sec;
	itval.it_interval.tv_nsec = ns;
	itval.it_value.tv_sec = sec;
	itval.it_value.tv_nsec = ns;

	if (timerfd_settime(fd, 0, &itval, NULL)) {
		log_error("Failed setting timer period.kn");
		return -1;
	}

	return fd;
}

static void update_ui(WINDOW *trace_win) {
	box(trace_win, 0, 0);
	trace_refresh_tui(trace_win);
	mvprintw(0, 0,  "'q' to quit, 'r' to reload symbols\n");
	mvprintw(1, 0, "Trace counter: %lu\n", trace_count);
	mvprintw(2, 0, "Total pages allocated: %lu\n", page_alloc_counter);
	mvprintw(3, 0, "Total pages Freed: %lu\n", page_free_counter);

	wrefresh(trace_win);
	refresh();
}

void tui_apply_fds(struct pollfd *fds) {
	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;

	fds[1].fd = gen_timerfd(1000 * 1000);
	fds[1].events = POLLIN;

	ui_fds = fds;
}

void tui_init(void) {
	int win_startx, win_starty, win_width, win_height;

	load_kallsyms();
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
	trace_refresh_tui(trace_win);
}

void tui_update(void) {
	int ch;

	if (ui_fds[0].revents & POLLIN) {
		/* On UI event */
		ch = getch();
		switch (ch) {
			case 'q':
				endwin();
				m_exit();
				return;

			case 'r':
				load_kallsyms();
				break;
		}
		update_ui(trace_win);
	}

	if (ui_fds[1].revents & POLLIN) {
		uint64_t time;
		read(ui_fds[1].fd, &time, sizeof(time));
		update_ui(trace_win);
	}
}
