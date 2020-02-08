include src/backend/Makefile

%.d: %.c
	@set -e; \
	$(CC) -MM $(CFLAGS) $(LDFLAGS) -MQ $(@:.d=.o) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.o: %.c
	$(CC) -c $(CFLAGS) $(LDFLAGS) -o $@ $(<:.d=.c)

LIB_SRCS = $(BACKEND_SRCS) \
	   src/tracing.c \
	   src/utils.c \
	   src/proc.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

MEMSTRACT_SRCS = src/memstrack.c
MEMSTRACT_OBJS = $(MEMSTRACT_SRCS:.c=.o) $(LIB_OBJS)
MEMSTRACT_DEPS = $(MEMSTRACT_OBJS:.o=.d)

memstrack: $(MEMSTRACT_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $+

include $(MEMSTRACT_DEPS)
