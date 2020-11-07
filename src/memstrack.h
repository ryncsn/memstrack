/*
 * memstrack.h
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
#include <stdio.h>

extern int m_debug;
extern int m_perf;
extern int m_ftrace;
extern int m_sort_alloc;
extern int m_sort_peak;
extern int m_notui;

extern int m_slab;
extern int m_page;

extern const char* m_report;
extern unsigned int page_size;

extern FILE* m_output;

#define LOG_LVL_DEBUG 0
#define LOG_LVL_INFO 1
#define LOG_LVL_WARN 2
#define LOG_LVL_ERROR 3

extern int m_log (int level, const char *__restrict __fmt, ...);

#define log_debug(...) m_log(LOG_LVL_DEBUG, __VA_ARGS__)
#define log_info(...) m_log(LOG_LVL_INFO, __VA_ARGS__)
#define log_warn(...) m_log(LOG_LVL_WARN, __VA_ARGS__)
#define log_error(...) m_log(LOG_LVL_ERROR, __VA_ARGS__)

extern void m_exit (int val);

#define SIZE_MB (1024 * 1024)
