/*
 * perf-events-define.h
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

#include <stdint.h>
#include <linux/perf_event.h>

#define GETN(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define NUMFIELDS(...) GETN(__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)

#define F_1(FN, VAL) FN VAL
#define F_2(FN, VAL, ...) FN VAL F_1(FN, __VA_ARGS__)
#define F_3(FN, VAL, ...) FN VAL F_2(FN, __VA_ARGS__)
#define F_4(FN, VAL, ...) FN VAL F_3(FN, __VA_ARGS__)
#define F_5(FN, VAL, ...) FN VAL F_4(FN, __VA_ARGS__)
#define F_6(FN, VAL, ...) FN VAL F_5(FN, __VA_ARGS__)
#define F_7(FN, VAL, ...) FN VAL F_6(FN, __VA_ARGS__)
#define F_8(FN, VAL, ...) FN VAL F_7(FN, __VA_ARGS__)
#define F_9(FN, VAL, ...) FN VAL F_8(FN, __VA_ARGS__)
#define F_10(FN, VAL, ...) FN VAL F_9(FN, __VA_ARGS__)
#define FORAPPLY(FN, ...) GETN(__VA_ARGS__, F_16, F_15, F_14, F_13, F_12, F_11, F_10, F_9, F_8, F_7, F_6, F_5, F_4, F_3, F_2, F_1) (FN, __VA_ARGS__)

#define ___DoDefineField(name, type, size, is_signed, ...)\
	{\
		#name,\
		#type,\
		size,\
		0,\
		is_signed,\
		0\
	},

#define __DoDefineField(name, type, size, ...)\
	___DoDefineField(name, type, size, ##__VA_ARGS__, (((type)-1) < 0))

#define _DoDefineField(name, type, ...)\
	__DoDefineField(name, type, ##__VA_ARGS__, sizeof(type))

#define _DoDefineTable(name, ...)\
	struct PerfEventField name##_info;

#define DefineEvent(event_class, name, buf_shift_min, sample_type, ...)\
	struct PerfEvent perf_event_##name = {\
		#event_class,\
		#name,\
		0,\
		sample_type,\
		buf_shift_min,\
		NUMFIELDS( __VA_ARGS__ ),\
		{\
			FORAPPLY(_DoDefineField, __VA_ARGS__)\
		}\
	};\
	struct __perf_event_field_table_##name {\
		FORAPPLY( _DoDefineTable, __VA_ARGS__)\
	}

#define EventField(type, name, ...) (name, type, ##__VA_ARGS__)

#define PerfEvent(name) &perf_event_##name

#define IncludeCommonEventFields()\
	EventField(unsigned short, common_type),\
	EventField(unsigned char, common_flags),\
	EventField(unsigned char, common_preempt_count),\
	EventField(int, common_pid)\

#define get_perf_event(name) perf_event_##name

#define get_perf_event_info(name)\
	((struct __perf_event_field_table_##name*)(perf_event_##name.fields))

#define get_perf_event_field_info(name, field)\
	get_perf_event_info(name)->field##_info

#define get_data_p_from_raw(raw_p)\
	((const unsigned char*)(&raw_p->data))

#define read_data_from_perf_raw(name, field, type, raw_p)\
	*((type*)(get_data_p_from_raw(raw_p) + get_perf_event_field_info(name, field).offset))

struct read_format {
	uint64_t value;			/* The value of the event */
	uint64_t time_enabled;		/* if PERF_FORMAT_TOTAL_TIME_ENABLED */
	uint64_t time_running;		/* if PERF_FORMAT_TOTAL_TIME_RUNNING */
	uint64_t id;			/* if PERF_FORMAT_ID */
};

struct read_format_group_hdr {
	uint64_t nr;			/* The number of events */
	uint64_t time_enabled;		/* if PERF_FORMAT_TOTAL_TIME_ENABLED */
	uint64_t time_running;		/* if PERF_FORMAT_TOTAL_TIME_RUNNING */
};

struct read_format_group_data {
	uint64_t value;			/* The value of the event */
	uint64_t id;			/* if PERF_FORMAT_ID */
};

struct perf_sample_id {
//	uint32_t pid;			/* if PERF_SAMPLE_TID set */
//	uint32_t tid;			/* if PERF_SAMPLE_TID set */
//	u64 time;			/* if PERF_SAMPLE_TIME set */
//	u64 id;				/* if PERF_SAMPLE_ID set */
//	u64 stream_id;			/* if PERF_SAMPLE_STREAM_ID set	*/
//	uint32_t cpu;			/* if PERF_SAMPLE_CPU set */
//	uint32_t res;			/* if PERF_SAMPLE_CPU set */
//	u64 id;				/* if PERF_SAMPLE_IDENTIFIER set */
};

struct perf_lost_events {
	struct perf_event_header header;
	uint64_t	id;
	uint64_t	lost;
	struct perf_sample_id sample_id;
};

struct perf_sample_callchain {
	uint64_t nr;			/* if PERF_SAMPLE_CALLCHAIN */
	uint64_t ips;			/* if PERF_SAMPLE_CALLCHAIN */
};

struct perf_sample_raw {
	uint32_t size;			/* if PERF_SAMPLE_RAW */
	const unsigned char data;	/* if PERF_SAMPLE_RAW */
};

struct perf_sample_data_loc_fixed {
	uint16_t size;
	uint16_t offset;
};

struct perf_sample__unused {
// 	uint64_t bnr;				/* if PERF_SAMPLE_BRANCH_STACK */
// 	struct perf_branch_entry lbr[bnr];	/* if PERF_SAMPLE_BRANCH_STACK */
// 	uint64_t abi;				/* if PERF_SAMPLE_REGS_USER */
// 	uint64_t regs[weight(mask)];		/* if PERF_SAMPLE_REGS_USER */
// 	uint64_t size;				/* if PERF_SAMPLE_STACK_USER */
// 	char data[size];			/* if PERF_SAMPLE_STACK_USER */
// 	uint64_t dyn_size;			/* if PERF_SAMPLE_STACK_USER && size != 0 */
// 	uint64_t weight;			/* if PERF_SAMPLE_WEIGHT */
// 	uint64_t data_src;			/* if PERF_SAMPLE_DATA_SRC */
// 	uint64_t transaction;			/* if PERF_SAMPLE_TRANSACTION */
// 	uint64_t abi;				/* if PERF_SAMPLE_REGS_INTR */
// 	uint64_t regs[weight(mask)];		/* if PERF_SAMPLE_REGS_INTR */
};
