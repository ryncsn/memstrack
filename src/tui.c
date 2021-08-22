/*
 * tui.c
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
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <poll.h>
#include <ncurses.h>

#include <sys/timerfd.h>
#include <sys/resource.h>

#include "memstrack.h"
#include "tracing.h"

#define MISC_PAD 2
#define NON_LAST_CHILD_INDENT '|'
#define NON_LAST_CHILD_PREFIX '+'
#define NON_LAST_CHILD_PREFIX_EXT '-'
#define LAST_CHILD_INDENT ' '
#define LAST_CHILD_PREFIX '+'
#define LAST_CHILD_PREFIX_EXT '-'

/* To manage tracenodes, sorted and indexed */
struct TracenodeView {
	union {
		bool expended;
		int height;
	};
	int pid;
	int rev_index;
	char *title;
	struct Record rec;
	struct Tracenode *tracenode;
	struct TracenodeView *parent;
};

static struct Tracenode **top_tracenodes;
static struct TracenodeView *tracenode_views;
static int top_tracenode_num;
static int tracenode_view_num;

static WINDOW *trace_win;

#define LINE_BUF_LEN 4096
static struct {
	int line_offset;
	int col_offset;
	int line_num;
	int highlight_line;
	int active_line_num;

	bool paused;
	bool console_too_small;

	int line_len;
	char *line_buf;
	char *line_cur;
} tui_info;

static enum {
	UI_TYPE_TASK = 0,
	UI_TYPE_MODULE,
	UI_TYPE_MAX
} ui_type;

static int is_tracenode_self(struct Tracenode* node, void *blob) {
	if (node == blob) {
		return 1;
	}

	return 0;
}

/* By the time the TUI try to access a tracenode,
 * it might have been released, check before access it */
static bool is_tracenode_view_stall(struct TracenodeView* node) {
	if (node->parent) {
		if (is_tracenode_view_stall(node->parent)) {
			return true;
		}

		if (for_each_tracenode_ret(
					node->parent->tracenode->children,
					is_tracenode_self, node->tracenode)) {
			return false;
		}

		return true;
	}

	/* Assumes top views won't stall */
	return false;
}

static void update_top_tracenodes(void) {
	if (tui_info.paused)
		return;

	if (top_tracenodes) {
		free(top_tracenodes);
		top_tracenodes = NULL;
	}

	if (ui_type == UI_TYPE_TASK) {
		top_tracenodes = (struct Tracenode**) collect_tasks_sorted(1, &top_tracenode_num);
	} else {
		top_tracenodes = (struct Tracenode**) collect_modules_sorted(1);
		top_tracenode_num = module_map.size;
	}
};

static void calc_tracenode_view_num_iter(struct Tracenode *node, void *_) {
	tracenode_view_num += 1;

	if (is_tracenode_extended(node)) {
		for_each_tracenode(node->children, calc_tracenode_view_num_iter, NULL);
	}
}

static void recalc_tracenode_view_num(void) {
	tracenode_view_num = 0;
	for (int i = 0; i < top_tracenode_num; ++i) {
		calc_tracenode_view_num_iter(top_tracenodes[i], NULL);
	}
}

struct sync_marker {
	struct TracenodeView *parent;
	int cur_row;
	int rev_index;
};

static int tracenode_view_sync(struct Tracenode *node, struct sync_marker *marker) {
	struct TracenodeView *view;

	view = &tracenode_views[marker->cur_row];
	marker->cur_row++;

	view->tracenode = node;
	view->parent = marker->parent;
	view->rev_index = marker->rev_index;
	view->height = 0;

	if (node->record)
		memcpy(&view->rec, node->record, sizeof(struct Record));
	else
		memset(&view->rec, 0, sizeof(struct Record));

	if (!node->parent) {
		if (ui_type == UI_TYPE_TASK) {
			struct Task *task = container_of(node, struct Task, tracenode);
			view->pid = task->pid;
			view->title = strdup(task->task_name);
		} else {
			struct Module *module = container_of(node, struct Module, tracenode);
			view->title = strdup(module->name);
		}
	} else {
		view->title = strdup(get_tracenode_symbol(node));
	}

	if (is_tracenode_extended(node)) {
		struct Tracenode** nodes;
		int count;

		nodes = collect_tracenodes_sorted(node->children, &count, 1);
		for (int i = 0; i < count; ++i) {
			marker->rev_index = count - i;
			marker->parent = view;
			view->height += tracenode_view_sync(nodes[i], marker);
		}

		free(nodes);
	}

	return view->height;
}

static void sync_tracenode_views(void) {
	struct sync_marker marker = { 0 };

	for (int i = 0; i < tracenode_view_num; ++i) {
		free(tracenode_views[i].title);
		tracenode_views[i].title = NULL;
	}

	recalc_tracenode_view_num();

	tracenode_views = realloc(tracenode_views, sizeof(struct TracenodeView) * tracenode_view_num);
	if (!tracenode_views && tracenode_view_num) {
		log_error("Out of memory\n");
		m_exit(1);
	}

	for (int i = 0; i < top_tracenode_num; ++i) {
		marker.rev_index = top_tracenode_num - i;
		marker.parent = NULL;
		tracenode_view_sync(top_tracenodes[i], &marker);
	}
}

static int toggle_tracenode_view(struct TracenodeView *view) {
	int ret = 0;

	if (is_tracenode_view_stall(view)) {
		return -1;
	}

	if (is_tracenode_extended(view->tracenode))
		unextend_tracenode(view->tracenode);
	else
		extend_tracenode(view->tracenode);

	return ret;
}

static struct pollfd *ui_fds;
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

void tui_apply_fds(struct pollfd *fds) {
	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;

	fds[1].fd = gen_timerfd(1000 * 1000);
	fds[1].events = POLLIN;

	ui_fds = fds;
}

static bool is_last_child(struct TracenodeView *view) {
	return view->rev_index == 1;
}

static int line_buf_putchar(char c) {
	if ((tui_info.line_cur - tui_info.line_buf) >= (tui_info.line_len - 1))
		return -1;

	*tui_info.line_cur = c;
	tui_info.line_cur++;

	return 0;
}

static int line_buf_puts(char *s) {
	int len = strlen(s);
	int left = (tui_info.line_len - (tui_info.line_cur - tui_info.line_buf + 1));

	if (left <= 0)
		return -1;

	if (left < len)
		len = left;

	/* Omit the \0, will always set a \0 later */
	strncpy(tui_info.line_cur, s, len);
	tui_info.line_cur += len;

	return 0;
}

static void print_tracenode_view(
		struct TracenodeView *view,
		int row)
{
	int title_offset;
	struct TracenodeView *parent;
	parent = view->parent;

	title_offset = strlen(view->title);
	if (tui_info.col_offset < title_offset)
		title_offset = tui_info.col_offset;

	if (!parent) {
		/* It's a task / module */
		if (ui_type == UI_TYPE_TASK) {
			snprintf(tui_info.line_buf, tui_info.line_len,
				 " %7d | %10ld | %10ld | ",
				 view->pid,
				 view->rec.pages_alloc,
				 view->rec.pages_alloc_peak);
			tui_info.line_cur = tui_info.line_buf + strlen(tui_info.line_buf);
			line_buf_puts(view->title + title_offset);
		} else {
			snprintf(tui_info.line_buf, tui_info.line_len,
				 "     [M] | %10ld | %10ld | ",
				 view->rec.pages_alloc,
				 view->rec.pages_alloc_peak);
			tui_info.line_cur = tui_info.line_buf + strlen(tui_info.line_buf);
			line_buf_puts(view->title + title_offset);
		}
	} else {
		char *st_start, *st_end;

		snprintf(tui_info.line_buf, tui_info.line_len,
			 "         | %10ld | %10ld | ",
			 view->rec.pages_alloc,
			 view->rec.pages_alloc_peak);
		tui_info.line_cur = tui_info.line_buf + strlen(tui_info.line_buf);

		st_start = tui_info.line_cur;
		while (parent) {
			line_buf_putchar(is_last_child(parent) ?
					LAST_CHILD_INDENT :
					NON_LAST_CHILD_INDENT);
			parent = parent->parent;
		}
		st_end = tui_info.line_cur - 1;

		while (st_start < st_end) {
			*st_start += *st_end;
			*st_end = *st_start - *st_end;
			*st_start -= *st_end;
			st_start++;
			st_end--;
		}

		line_buf_putchar(is_last_child(view) ?
				 view->expended ?
					 LAST_CHILD_PREFIX_EXT : LAST_CHILD_PREFIX :
				 view->expended ?
					 NON_LAST_CHILD_PREFIX_EXT : NON_LAST_CHILD_PREFIX);
		line_buf_putchar(' ');
		line_buf_puts(view->title + title_offset);
	}

	*tui_info.line_cur = '\0';
	tui_info.line_buf[tui_info.line_len] = '\0';

	if (row == tui_info.highlight_line) {
		wattron(trace_win, A_REVERSE);
		mvwprintw(trace_win, row + 1, 1,  "%s", tui_info.line_buf);
		wattroff(trace_win, A_REVERSE);
	} else {
		mvwprintw(trace_win, row + 1, 1,  "%s", tui_info.line_buf);
	}
}

static void update_tracewin(void) {
	/* Clean up the window */
	werase(trace_win);
	box(trace_win, 0, 0);

	/* Window title bar */
	if (ui_type == UI_TYPE_TASK) {
		mvwprintw(trace_win, 0, 1, "   PID   |    Pages   |    Peak    |   Process Command Line\n");
	} else {
		mvwprintw(trace_win, 0, 1, "         |    Pages   |    Peak    |   Module Name   \n");
	}

	if (tui_info.highlight_line >= tui_info.active_line_num)
		tui_info.highlight_line = tui_info.active_line_num - 1;

	if (tui_info.highlight_line < 0)
		tui_info.highlight_line = 0;

	if (tui_info.highlight_line < 0)
		tui_info.highlight_line = 0;

	if (tui_info.line_offset > tracenode_view_num - tui_info.line_num)
		tui_info.line_offset = tracenode_view_num - tui_info.line_num;

	if (tui_info.line_offset < 0)
		tui_info.line_offset = 0;

	if (tui_info.col_offset < 0)
		tui_info.col_offset = 0;

	tui_info.active_line_num = 0;
	for (int i = 0, j; i < tui_info.line_num; ++i) {
		j = tui_info.line_offset + i;
		if (j >= tracenode_view_num)
			break;

		tui_info.active_line_num++;
		print_tracenode_view(tracenode_views + j, i);
	}

	wrefresh(trace_win);
}

static void ui_update_size(void) {
	int win_startx, win_starty, win_width, win_height;

	win_height = LINES - MISC_PAD;
	win_width = COLS;
	win_starty = MISC_PAD;
	win_startx = 0;

	if (win_width < 16 || win_height < 8) {
		tui_info.console_too_small = 1;
		return;
	} else {
		tui_info.console_too_small = 0;
	}

	if (tui_info.line_num != win_height - 2 ||
	    tui_info.line_len != win_width - 2)
	{
		if (trace_win)
			delwin(trace_win);
		trace_win = NULL;

		if (tui_info.line_buf)
			free(tui_info.line_buf);
		tui_info.line_buf = NULL;

		tui_info.line_len = COLS - 2;
		tui_info.line_num = LINES - MISC_PAD - 2;
	}

	if (!trace_win)
		trace_win = newwin(win_height, win_width, win_starty, win_startx);

	if (!tui_info.line_buf)
		tui_info.line_buf = malloc(tui_info.line_len + 1);
}

static void update_ui(void) {
	ui_update_size();

	if (tui_info.console_too_small) {
		mvprintw(0, 0, "Console is too small\n");
		refresh();
		return;
	}

	mvprintw(0, 0,  "'q': quit, 'r': reload symbols, 'm': switch processes/modules, 'p': pause UI\n");
	mvprintw(1, 0, "Pages being tracked: %lu (%luMB)\n",
			(page_alloc_counter - page_free_counter),
			(page_alloc_counter - page_free_counter) * page_size / SIZE_MB);
	refresh();

	update_tracewin();
}

void tui_init(void) {
	need_page_free_always_backtrack();
	need_tracenode_extendable();

	load_kallsyms();
	initscr();
	keypad(stdscr, TRUE);
	timeout(-1);
	curs_set(0);
	noecho();
	raw();
}

void tui_loop(void) {
	int ch;
	int ret;

	if (ui_fds[0].revents & POLLIN) {
		/* On UI event */
		ch = getch();
		switch (ch) {
			case 'q':
			case 'Q':
				endwin();
				m_exit(0);
				return;

			case 'm':
			case 'M':
				ui_type++;
				if (ui_type >= UI_TYPE_MAX)
					ui_type = 0;
				update_top_tracenodes();
				sync_tracenode_views();
				break;

			case 'r':
			case 'R':
				load_kallsyms();
				break;

			case ' ':
				toggle_tracenode_view(tracenode_views + tui_info.highlight_line + tui_info.line_offset);
				sync_tracenode_views();
				break;

			case 'p':
			case 'P':
				tui_info.paused = !tui_info.paused;
				break;

			case KEY_RIGHT:
				tui_info.col_offset++;
				break;

			case KEY_LEFT:
				tui_info.col_offset--;
				break;

			case KEY_UP:
				tui_info.highlight_line--;
				if (tui_info.highlight_line < 0) {
					tui_info.line_offset--;
				}
				break;

			case KEY_DOWN:
				tui_info.highlight_line++;
				if (tui_info.highlight_line >= tui_info.line_num) {
					tui_info.line_offset++;
				}
				break;
		}

		update_ui();
	}

	if (ui_fds[1].revents & POLLIN) {
		uint64_t time;
		ret = read(ui_fds[1].fd, &time, sizeof(time));
		if (ret) {
			update_top_tracenodes();
			sync_tracenode_views();
			update_ui();
		}
	}
}
