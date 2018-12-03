CC = gcc
CFLAGS = -std=c11 -g -O0
MEMORY_TRACER_OBJ = src/memory-tracer.o src/tracing.o src/utils.o src/perf.o src/ftrace.o

all: memory-tracer

utils.o: src/utils.c src/utils.h
perf.o: src/perf.c src/memory-tracer.h src/perf.h
ftrace.o: src/ftrace.c src/memory-tracer.h src/ftrace.h
tracing.o: src/tracing.c src/memory-tracer.h src/tracing.h src/utils.h
memory-tracer.o: src/memory-tracer.c src/memory-tracer.h src/tracing.h \
 src/utils.h src/ftrace.h src/perf.h

memory-tracer: $(MEMORY_TRACER_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(MEMORY_TRACER_OBJ)

.PHONY: clean
clean:
	rm -f $(MEMORY_TRACER_OBJ) memory-tracer
