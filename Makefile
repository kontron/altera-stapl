TOPDIR := $(shell pwd)

PACKAGE := altera-stapl
VERSION := 0.2
TARGET_ARCH := $(if $(TARGET_PREFIX),$(patsubst %-,%,$(TARGET_PREFIX)),$(shell uname -m))

# install directories
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

ifeq ($(shell test -d .git && echo 1),1)
VERSION := $(shell git describe --dirty --tags --always)
endif

EXTRA_CFLAGS = -Wall -Wno-pointer-sign -DVERSION=\"$(VERSION)\"

SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
DIST    := Makefile COPYING README.md $(SOURCES) $(wildcard *.h)

programs = jbi

.PHONY: all install
all: altera-stapl

clean:
	rm -f $(OBJECTS)

%.o: %.c
	$(CC) -c $< $(CLFAGS) $(EXTRA_CFLAGS)

altera-stapl: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

install: altera-stapl
	install -D -m 0755 altera-stapl $(DESTDIR)$(BINDIR)/altera-stapl

dist:
	tar --transform 's,^,$(PACKAGE)-$(VERSION)/,' -czf $(PACKAGE)-$(VERSION).tar.gz $(DIST)

install-tgz:
	rm -rf /tmp/$(PACKAGE)-$(VERSION)
	make install DESTDIR=/tmp/$(PACKAGE)-$(VERSION) PREFIX=/usr/local
	tar -czf $(PACKAGE)-$(VERSION).bin.$(TARGET_ARCH).tgz -C /tmp/$(PACKAGE)-$(VERSION) . --owner=0 --group=0
	rm -rf /tmp/$(PACKAGE)-$(VERSION)
