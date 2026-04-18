CC := clang
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude -MMD -MP
LDFLAGS :=
BUILD_DIR := build
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
EXE_SUFFIX :=
BIN_NAME := cld

ifeq ($(OS),Windows_NT)
EXE_SUFFIX := .exe
BIN_NAME := cld.exe
endif

TARGET := $(BUILD_DIR)/cld$(EXE_SUFFIX)
BIN_DIR_FINAL := $(DESTDIR)$(BINDIR)
SOURCES := $(wildcard src/*.c)
OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
DEPS := $(OBJECTS:.o=.d)

.PHONY: all clean test install uninstall

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@-mkdir "$(BUILD_DIR)"
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: src/%.c
	@-mkdir "$(BUILD_DIR)"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -rf "$(BUILD_DIR)"
	-rmdir /S /Q "$(BUILD_DIR)"

test: $(TARGET)
	./tests/macos/run.sh
	./tests/elf/run.sh
	./tests/bslash/run.sh

install: $(TARGET)
ifeq ($(OS),Windows_NT)
	@-mkdir "$(BIN_DIR_FINAL)"
	copy /Y "$(TARGET)" "$(BIN_DIR_FINAL)\\$(BIN_NAME)" >nul
else
	install -d "$(BIN_DIR_FINAL)"
	install -m 755 "$(TARGET)" "$(BIN_DIR_FINAL)/$(BIN_NAME)"
endif

uninstall:
ifeq ($(OS),Windows_NT)
	-del /Q "$(BIN_DIR_FINAL)\\$(BIN_NAME)"
else
	rm -f "$(BIN_DIR_FINAL)/$(BIN_NAME)"
endif

-include $(DEPS)
