CC = gcc
CFLAGS = -std=c11 -g -O0
ANALYZER_OBJS = src/analyzer.o src/tracing.o src/utils.o

all: analyzer

analyzer.o: src/analyzer.c src/tracing.h src/utils.h src/analyzer.h
tracing.o: src/tracing.c src/tracing.h src/utils.h
utils.o: src/utils.c src/utils.h

analyzer: $(ANALYZER_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(ANALYZER_OBJS)

.PHONY: clean
clean:
	rm -f $(ANALYZER_OBJS) analyzer
