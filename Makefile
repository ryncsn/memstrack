prefix ?= /usr
libdir ?= ${prefix}/lib
datadir ?= ${prefix}/share
pkglibdir ?= ${libdir}/dracut
sysconfdir ?= ${prefix}/etc
bindir ?= ${prefix}/bin
mandir ?= ${prefix}/share/man
dracutlibdir ?= ${prefix}/lib/dracut

CC = gcc
CFLAGS = -std=c11 -g -O2
MEMORY_TRACER_OBJ = src/memory-tracer.o src/tracing.o src/utils.o src/perf.o src/perf-handler.o src/ftrace.o src/ftrace-handler.o src/proc.o

all: memory-tracer

utils.o: src/utils.c src/utils.h
tracing.o: src/tracing.c src/memory-tracer.h src/tracing.h src/utils.h
ftrace.o: src/ftrace.c src/memory-tracer.h src/ftrace.h
ftrace-handler.o: src/ftrace-handler.c src/memory-tracer.h src/tracing.h src/utils.h src/ftrace.h
perf.o: src/perf.c src/memory-tracer.h src/perf.h
perf-handler.o: src/perf-handler.c src/memory-tracer.h src/tracing.h src/utils.h src/perf.h
proc.o: src/proc.c src/proc.h
memory-tracer.o: src/memory-tracer.c src/perf-handler.h src/tracing.h src/utils.h src/ftrace-handler.h src/memory-tracer.h

memory-tracer: $(MEMORY_TRACER_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(MEMORY_TRACER_OBJ)

.PHONY: clean
clean:
	rm -f $(MEMORY_TRACER_OBJ) memory-tracer

install: all
	mkdir -p $(DESTDIR)$(pkglibdir)
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(sysconfdir)
	mkdir -p $(DESTDIR)$(pkglibdir)/modules.d
	mkdir -p $(DESTDIR)$(mandir)/man1 $(DESTDIR)$(mandir)/man5 $(DESTDIR)$(mandir)/man7 $(DESTDIR)$(mandir)/man8
	install -m 0755 memory-tracer $(DESTDIR)$(bindir)/memory-tracer

dracut-module-install: install
	mkdir -p $(DESTDIR)$(dracutlibdir)/modules.d/99memory-tracer
	cp misc/99memory-tracer/module-setup.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memory-tracer/module-setup.sh
	cp misc/99memory-tracer/start-tracing.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memory-tracer/start-tracing.sh
	cp misc/99memory-tracer/stop-tracing.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memory-tracer/stop-tracing.sh
