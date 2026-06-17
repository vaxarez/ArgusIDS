# ArgusIDS — Linux only
#   make          build binary
#   make install  install to PREFIX (default /usr/local)
#   make clean    remove build artifacts
#   make uninstall

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -std=c11
CFLAGS  += -Iinclude -Isrc
LDFLAGS ?=

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

BUILD_DIR = build
TARGET    = $(BUILD_DIR)/argusids

SRCS = src/main.c \
       src/capture/capture.c \
       src/parse/packet.c \
       src/detect/detector.c \
       src/log/alert.c

OBJS = $(SRCS:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean install uninstall help

all: $(TARGET)
	@echo ""
	@echo "Build complete: $(TARGET)"
	@echo "Run: sudo ./$(TARGET)"

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)/capture $(BUILD_DIR)/parse $(BUILD_DIR)/detect $(BUILD_DIR)/log

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/argusids
	@echo "Installed: $(DESTDIR)$(BINDIR)/argusids"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/argusids
	@echo "Removed: $(DESTDIR)$(BINDIR)/argusids"

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "ArgusIDS build targets:"
	@echo "  make              Compile to build/argusids"
	@echo "  make install      Install to $(BINDIR) (use sudo)"
	@echo "  make uninstall    Remove installed binary"
	@echo "  make clean        Delete build/"
	@echo ""
	@echo "Options:"
	@echo "  PREFIX=/opt/argus make install"
	@echo "  CC=clang make"
