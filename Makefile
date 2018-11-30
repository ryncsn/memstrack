CC = gcc
CFLAGS = -std=c11 -g -O0
ANALYZER_OBJS = src/analyzer.o src/tracing.o src/utils.o src/perf.o src/ftrace.o

all: analyzer

analyzer.o: src/analyzer.c src/analyzer.h src/utils.h src/tracing.h src/perf.h src/ftrace.h
ftrace.o: src/ftrace.c src/ftrace.h
perf.o: src/perf.c src/perf.h
tracing.o: src/tracing.c src/tracing.h src/utils.h
utils.o: src/utils.c src/utils.h

analyzer: $(ANALYZER_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(ANALYZER_OBJS)

.PHONY: clean
clean:
	rm -f $(ANALYZER_OBJS) analyzer
