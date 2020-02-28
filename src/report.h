#include "utils.h"

struct reporter_table_t {
	char *name;
	void (*report)(void);
};

extern struct reporter_table_t reporter_table[];
extern int report_table_size;

void final_report(struct HashMap *task_map, int task_limit);
