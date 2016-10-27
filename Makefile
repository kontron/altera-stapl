TOPDIR := $(shell pwd)

VERSION := 0.1

# install directories
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

ifeq ($(shell test -d .git && echo 1),1)
VERSION := $(shell git describe --abbrev=8 --dirty --always --tags --long)
endif

EXTRA_CFLAGS = -Wall -Wno-pointer-sign -DVERSION=\"$(VERSION)\"

SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)

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
