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

#define rev_mvprintw(...) do {attron(A_REVERSE); mvprintw(__VA_ARGS__); attroff(A_REVERSE);} while(0)

struct TracenodeView {
	bool expended;
};

static struct pollfd *ui_fds;

static WINDOW *trace_win;

static struct Task **sorted_tasks;
static int tasks_num;
static void update_top_tasks() {
	if (sorted_tasks)
		free(sorted_tasks);

	// TODO: No need to free / alloc every time
	sorted_tasks = collect_tasks_sorted(1);
	tasks_num = task_map.size;

	for (int i = 0; i < tasks_num; ++i) {
		if (!to_tracenode(sorted_tasks[i])->record->blob)
			to_tracenode(sorted_tasks[i])->record->blob = calloc(1, sizeof(struct TracenodeView));
	}
};

/*
 * For tracenode info output
 * TODO: Use a window properly
 */
static int line_highlight;

struct line_info {
	int offset;
	int limit;
	int current;
	char buffer[1024];
} *info;

static int tui_print_tracenode(struct Tracenode *node, int indent) {
	struct Tracenode** nodes;
	struct TracenodeView *view;

	int count, ret = 0;
	char expand_sym;

	if (!node->record->blob)
		node->record->blob = calloc(1, sizeof(struct TracenodeView));

	view = node->record->blob;

	if (view->expended)
		expand_sym = '|';
	else
		expand_sym = '+';

	if (indent == 0) {
		/* It's a task */
		struct Task *task = container_of(node, struct Task, tracenode);
		sprintf(info->buffer, "%c %7ld | %10ld | %s\n", expand_sym, task->pid, task->tracenode.record->pages_alloc, task->task_name);
	} else {
		int i; for (i = 0; i < indent; ++i)
			info->buffer[i] = ' ';

		sprintf(info->buffer + i, "%c | %10ld | %s\n", expand_sym, node->record->pages_alloc, get_tracenode_symbol(node));
	}

	info->buffer[COLS - 2] = '\0';
	if (info->current == line_highlight)
		rev_mvprintw(info->offset + info->current, 1,  "%s", info->buffer);
	else
		mvprintw(info->offset + info->current, 1,  "%s", info->buffer);

	if (info->current++ > info->limit)
		return -1;

	if (view->expended && node->children) {
		nodes = collect_tracenodes_sorted(node->children, &count, 1);
		for (int i = 0; i < count; ++i) {
			ret = tui_print_tracenode(nodes[i], indent + 1);
			if (ret)
				break;
		}
		free(nodes);
	}

	return ret;
}

static void trace_refresh_tui() {
	struct line_info line_info;
	line_info.current = 0;
	line_info.limit = LINES - MISC_PAD - 4;
	line_info.offset = MISC_PAD + 1;

	info = &line_info;

	for (int task_n = 0; task_n < tasks_num; ++task_n) {
		if (tui_print_tracenode(to_tracenode(sorted_tasks[task_n]), 0))
			return;
	}
}

static int try_extend_tracenode(struct Tracenode *node, int is_task) {
	struct Tracenode** nodes;
	struct TracenodeView *view;
	int count, ret = 0;

	if (!node->record->blob)
		node->record->blob = calloc(1, sizeof(struct TracenodeView));
	view = node->record->blob;

	if (info->current++ == line_highlight) {
		view->expended = !view->expended;
		// TODO: When should all sub records be freed?
		// if (!view->expended && !is_task) {
		// 	depopulate_tracenode(node);
		// }
		return -1;
	}

	if (view->expended && node->children) {
		nodes = collect_tracenodes_sorted(node->children, &count, 1);
		for (int i = 0; i < count; ++i) {
			ret = try_extend_tracenode(nodes[i], 0);
			if (ret)
				break;
		}
		free(nodes);
	}

	return ret;
}

static void expend_line(int line) {
	struct line_info line_info;

	line_info.current = 0;
	line_info.limit = LINES - MISC_PAD - 3;
	line_info.offset = MISC_PAD + 1;

	info = &line_info;

	for (int task_n = 0; task_n < tasks_num; ++task_n) {
		if (try_extend_tracenode(to_tracenode(sorted_tasks[task_n]), 1))
			break;
	}

	trace_refresh_tui();
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
	mvprintw(0, 0,  "'q' to quit, 'r' to reload symbols\n");
	mvprintw(1, 0, "Trace counter: %lu\n", trace_count);
	mvprintw(2, 0, "Total pages allocated: %lu\n", page_alloc_counter);
	mvprintw(3, 0, "Total pages Freed: %lu\n", page_free_counter);

	update_top_tasks();
	trace_refresh_tui();
	wrefresh(trace_win);
	box(trace_win, 0, 0);
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
}

void tui_update(void) {
	int ch;

	if (ui_fds[0].revents & POLLIN) {
		/* On UI event */
		ch = getch();
		switch (ch) {
			case 'q':
				endwin();
				m_exit(0);
				return;

			case 'r':
				load_kallsyms();
				break;

			case ' ':
				expend_line(line_highlight + MISC_PAD);
				break;

			case KEY_UP:
				line_highlight--;
				if (line_highlight < 0)
					line_highlight = 0;
				break;

			case KEY_DOWN:
				line_highlight++;
				if (line_highlight > LINES - MISC_PAD)
					line_highlight = LINES - MISC_PAD;
		}
		update_ui(trace_win);
	}

	if (ui_fds[1].revents & POLLIN) {
		uint64_t time;
		read(ui_fds[1].fd, &time, sizeof(time));
		update_ui(trace_win);
	}
}
