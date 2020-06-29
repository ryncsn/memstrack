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
CFLAGS := -Os -g -std=c11 -fPIC $(CFLAGS)
LDFLAGS := $(LDFLAGS)
LIBS := -lncurses

include src/Makefile

all: memstrack

.PHONY: clean
clean:
	rm -f $(DEP_FILES:.o=.d)
	rm -f $(OBJ_FILES)
	rm -f $(OUT_FILES)
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
	cp misc/99memstrack/memstrack.service $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack/memstrack.service
	cp misc/99memstrack/memstrack-start.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack/memstrack-start.sh
	cp misc/99memstrack/memstrack-report.sh $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack/memstrack-report.sh

uninstall:
	rm $(DESTDIR)$(bindir)/memstrack

test: unittests-run memstrack
	sudo misc/selftest.sh

dracut-module-uninstall:
	rm -rf $(DESTDIR)$(dracutlibdir)/modules.d/99memstrack
