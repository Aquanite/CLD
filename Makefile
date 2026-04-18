CC := clang
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude -MMD -MP
LDFLAGS :=
BUILD_DIR := build
TARGET := $(BUILD_DIR)/cld
TARGET_EXE := $(TARGET).exe
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
BIN_NAME := cld

ifeq ($(OS),Windows_NT)
BIN_NAME := cld.exe
endif

SOURCES := $(wildcard src/*.c)
OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
DEPS := $(OBJECTS:.o=.d)

.PHONY: all clean test install uninstall

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

test: $(TARGET)
	./tests/macos/run.sh
	./tests/elf/run.sh
	./tests/bslash/run.sh

install: $(TARGET)
	install -d "$(DESTDIR)$(BINDIR)"
	@if [ -f "$(TARGET)" ]; then \
		install -m 755 "$(TARGET)" "$(DESTDIR)$(BINDIR)/$(BIN_NAME)"; \
	elif [ -f "$(TARGET_EXE)" ]; then \
		install -m 755 "$(TARGET_EXE)" "$(DESTDIR)$(BINDIR)/$(BIN_NAME)"; \
	else \
		echo "missing build target: $(TARGET) or $(TARGET_EXE)"; \
		exit 1; \
	fi

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN_NAME)"

-include $(DEPS)