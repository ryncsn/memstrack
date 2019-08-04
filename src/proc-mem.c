#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include "memory-tracer.h"

#define MAX_LINE 1024
#define SLABINFO "/proc/slabinfo"
#define SLABINFO_DEBUG_HEAD "slabinfo - version: 2.1 (statistics)\n"
#define SLABINFO_HEAD "slabinfo - version: 2.1\n"
#define SLAB_NAME_LEN 18

// For non debug case
struct slab_info {
	char name[SLAB_NAME_LEN];
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned int objsize;
	unsigned int objperslab;
	unsigned int pagesperslab;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int sharedfactor;
	unsigned long active_slabs;
	unsigned long num_slabs;
	unsigned long sharedavail;
};

static struct slab_info *slab_info_table;
static int slab_info_size = 0, slab_info_number = 0;

static int sort_slab(const void *a, const void *b) {
	struct slab_info *info_a = (struct slab_info*)a;
	struct slab_info *info_b = (struct slab_info*)b;

	return (info_b->num_slabs * info_b->pagesperslab) - (info_a->num_slabs * info_a->pagesperslab);
}

int print_slab_usage()
{
	FILE *file;
	char line[MAX_LINE];
	int slab_debug, total_pages, entry_number;
	struct slab_info *entry;

	file = fopen("/proc/slabinfo", "r");
	if (!file) {
		return -EINVAL;
	}

	entry_number = 0;
	total_pages = 0;

	for (int line_number = 0; fgets(line, MAX_LINE, file); ++line_number) {
		if (line_number == 0) {
			if (!strncmp(line, SLABINFO_DEBUG_HEAD, sizeof(SLABINFO_DEBUG_HEAD))) {
				slab_debug = 1;
			} else if (!strncmp(line, SLABINFO_HEAD, sizeof(SLABINFO_HEAD))) {
				slab_debug = 0;
			} else {
				/* Unrecognized ? */
				fclose(file);
				return -EINVAL;
			}
			continue;
		}

		/* Skip the header */
		if (line_number == 1) {
			continue;
		}

		entry_number = line_number - 2;
		if (entry_number >= slab_info_number) {
			slab_info_number = entry_number;
			if (slab_info_number >= slab_info_size) {
				if (slab_info_size == 0) {
					slab_info_size = 32;
					slab_info_table = malloc(slab_info_size * sizeof(*slab_info_table));
				} else {
					struct slab_info *slab_info_new;

					slab_info_size *= 2;
					slab_info_new = malloc(slab_info_size * sizeof(*slab_info_table));
					memcpy(slab_info_new, slab_info_table, sizeof(*slab_info_table) * slab_info_size / 2);
					free(slab_info_table);
					slab_info_table = slab_info_new;
				}
			}
		}

		entry = &slab_info_table[entry_number];

		sscanf(line, "%s %lu %lu %u %u %d : tunables %u %u %u : slabdata %lu %lu %lu",
				entry->name, &entry->active_objs, &entry->num_objs,
				&entry->objsize, &entry->objperslab, &entry->pagesperslab,
				&entry->limit, &entry->batchcount, &entry->sharedfactor,
				&entry->active_slabs, &entry->num_slabs, &entry->sharedavail);

		total_pages += entry->num_slabs * entry->pagesperslab;
	}

	slab_info_number = entry_number;
	qsort((void*)slab_info_table, slab_info_number, sizeof(struct slab_info), sort_slab);

	log_info("Top Slab Usage:\n");
	for (int i = 0; i < slab_info_number; ++i) {
		entry = &slab_info_table[i];
		unsigned long size_in_mb = entry->num_slabs * entry->pagesperslab * page_size / 1024 / 1024;
		log_info("%17s: %lu MB\n", entry->name, size_in_mb);
	}

	return 0;
}


int get_slab_usage() {
	FILE *file;
	file = fopen(SLABINFO, "r");

	if (!file) {
		return -EINVAL;
	}

	return 0;
}
