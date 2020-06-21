include src/backend/Makefile

%.d: %.c
	@set -e; \
	$(CC) -MM $(CFLAGS) $(LDFLAGS) -MQ $(@:.d=.o) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.o: %.c
	$(CC) -c $(CFLAGS) $(LDFLAGS) -o $@ $(<:.d=.c)

MEMSTRACT_SRCS = $(BACKEND_SRCS) \
	   src/report.c \
	   src/tracing.c \
	   src/utils.c \
	   src/tui.c \
	   src/proc.c
MEMSTRACT_OBJS = $(MEMSTRACT_SRCS:.c=.o)
MEMSTRACT_DEPS = $(MEMSTRACT_OBJS:.o=.d)

MEMSTRACT_MAIN_SRCS = src/memstrack.c
MEMSTRACT_MAIN_OBJS = $(MEMSTRACT_MAIN_SRCS:.c=.o)
MEMSTRACT_MAIN_DEPS = $(MEMSTRACT_MAIN_OBJS:.o=.d)

memstrack: $(MEMSTRACT_MAIN_OBJS) $(MEMSTRACT_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $+

# Unit test rules
MEMSTRACT_TEST_SRCS = $(wildcard src/tests/*.c)
MEMSTRACT_TEST_OBJS = $(MEMSTRACT_TEST_SRCS:.c=.o)
MEMSTRACT_TEST_DEPS = $(MEMSTRACT_TEST_OBJS:.o=.d)
MEMSTRACT_TESTS = $(patsubst %.o,%,$(MEMSTRACT_TEST_OBJS))

$(MEMSTRACT_TESTS): % : %.o $(MEMSTRACT_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(MEMSTRACT_OBJS)

.PHONY: unittest
unittests: $(MEMSTRACT_TESTS)

.PHONY: run-unittests
run-unittests: $(MEMSTRACT_TESTS)
	@echo "STARTING UNIT TESTS";
	@echo "---------------------------------------------------";
	@for f in $(MEMSTRACT_TESTS); do\
		echo "EXECUTING TEST: $${f}";\
		echo "---------------------------------------------------";\
		sh -c "$${f} && printf '\nTEST PASSED\n' || printf '\nTEST FAILED\n'";\
		echo "---------------------------------------------------";\
	done

# Include all dependencies
include $(MEMSTRACT_DEPS)
include $(MEMSTRACT_MAIN_DEPS)
include $(MEMSTRACT_TEST_DEPS)

# For clean up, all generated files are here:
DEP_FILES = $(MEMSTRACT_DEPS) $(MEMSTRACT_MAIN_DEPS) $(MEMSTRACT_TEST_DEPS)
OBJ_FILES = $(MEMSTRACT_OBJS) $(MEMSTRACT_MAIN_OBJS) $(MEMSTRACT_TEST_OBJS)
OUT_FILES = $(MEMSTRACT_TESTS) memstrack
