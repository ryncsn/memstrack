prefix ?= /usr
libdir ?= ${prefix}/lib
datadir ?= ${prefix}/share
pkglibdir ?= ${libdir}/memstrack
sysconfdir ?= ${prefix}/etc
bindir ?= ${prefix}/bin
mandir ?= ${prefix}/share/man
dracutlibdir ?= ${prefix}/lib/dracut

CC = gcc
CFLAGS = -std=c11 -g -O2
MEMORY_TRACER_OBJ = src/memstrack.o src/tracing.o src/utils.o src/perf.o src/perf-handler.o src/ftrace.o src/ftrace-handler.o src/proc.o

all: memstrack

utils.o: src/utils.c src/utils.h
tracing.o: src/tracing.c src/memstrack.h src/tracing.h src/utils.h
ftrace.o: src/ftrace.c src/memstrack.h src/ftrace.h
ftrace-handler.o: src/ftrace-handler.c src/memstrack.h src/tracing.h src/utils.h src/ftrace.h
perf.o: src/perf.c src/memstrack.h src/perf.h
perf-handler.o: src/perf-handler.c src/memstrack.h src/tracing.h src/utils.h src/perf.h
proc.o: src/proc.c src/proc.h
memstrack.o: src/memstrack.c src/perf-handler.h src/tracing.h src/utils.h src/ftrace-handler.h src/memstrack.h

memstrack: $(MEMORY_TRACER_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(MEMORY_TRACER_OBJ)

.PHONY: clean
clean:
	rm -f $(MEMORY_TRACER_OBJ) memstrack

install: all
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(sysconfdir)
	mkdir -p $(DESTDIR)$(pkglibdir)/modules.d
	mkdir -p $(DESTDIR)$(mandir)/man1 $(DESTDIR)$(mandir)/man5 $(DESTDIR)$(mandir)/man7 $(DESTDIR)$(mandir)/man8
	install -m 0755 memstrack $(DESTDIR)$(bindir)/memstrack

dracut-module-install: install
	mkdir -p $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack
	cp misc/99memstrack/module-setup.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack/module-setup.sh
	cp misc/99memstrack/start-tracing.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack/start-tracing.sh
	cp misc/99memstrack/stop-tracing.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack/stop-tracing.sh
	cp misc/99memstrack/memstrack.service $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack/memstrack.service

uninstall:
	rm $(DESTDIR)$(bindir)/memstrack

dracut-module-uninstall:
	rm -rf $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack
