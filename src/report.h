/*
 * report.h
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

#include "utils.h"

enum reporter_sort_by {
	SORT_BY_ALLOC = 0, /* default */
	SORT_BY_PEAK
};

struct reporter_fmt {
	enum reporter_sort_by sort_by;
	int throttle;
	int top;
};

struct reporter_table_t {
	char *name;
	void (*report)(struct reporter_fmt* fmt);
};

extern struct reporter_table_t reporter_table[];
extern int report_table_size;
extern int report_default_throttle;

int check_report_fmt(const char *fmt);
void do_report(const char* fmt);
