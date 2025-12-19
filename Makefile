CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -pedantic
CFLAGS += -pthread
C_SRC := src/c/sysmon.c
C_BIN := webmon
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
INSTALL ?= install

.PHONY: run build-c run-c clean-c install uninstall

build-c:
	@$(CC) $(CFLAGS) $(C_SRC) -o $(C_BIN)

run-c: build-c
	@./$(C_BIN)

clean-c:
	@rm -f $(C_BIN)

run: run-c

install: build-c
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(C_BIN) $(DESTDIR)$(BINDIR)/$(C_BIN)

uninstall:
	@rm -f $(DESTDIR)$(BINDIR)/$(C_BIN)
