srcdir ?= src
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
LDFLAGS = -lncurses

include src/Makefile

all: memstrack

.PHONY: clean
clean:
	@rm -f $(MEMSTRACT_OBJS:.o=.d)
	rm -f $(MEMSTRACT_OBJS)
	rm -f memstrack

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
