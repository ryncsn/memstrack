#define _GNU_SOURCE

#include "../../proc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

const char* zone_info_fixture = \
"Node 0, zone   Normal\n"
"  pages free     99850\n"
"        min      18753\n"
"        low      22545\n"
"        high     26337\n"
"        spanned  3663872\n"
"        present  3663872\n"
"        managed  3583541\n"
"  start_pfn:           1048576\n"
"";

const char* zone_info_tempfile = "/tmp/.memstrack-zone-fixture";

FILE *fopen(const char *path, const char *mode) {
	FILE *tmp;
	FILE *(*original_fopen)(const char*, const char*);

	original_fopen = dlsym(RTLD_NEXT, "fopen");

	if (strncmp(path, ZONEINFO, sizeof(ZONEINFO)) == 0) {
		tmp = (*original_fopen)(zone_info_tempfile, "w");
		if (!tmp)
			return NULL;

		fprintf(tmp, "%s", zone_info_fixture);
		fclose(tmp);

		return (*original_fopen)(zone_info_tempfile, mode);
	} else {
		return (*original_fopen)(path, mode);
	}
}
