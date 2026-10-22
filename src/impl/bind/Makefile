# librootview.so: the engine and the rv_* api, without the command-line front ends

ROOT := ../../..
IMPL_DIR := $(ROOT)/src/impl
INTF_DIR := $(ROOT)/src/intf
BIND_DIR := $(IMPL_DIR)/bind
BUILD_DIR := $(ROOT)/build/pic
TARGET := $(ROOT)/librootview.so

CC := gcc
CFLAGS := -Wall -Wextra -O2 -g -fPIC -fvisibility=hidden -I$(INTF_DIR) $(shell pkg-config --cflags libvmi)
LDFLAGS := -shared $(shell pkg-config --libs libvmi) -lvirt -Wl,-rpath,'$$ORIGIN' -Wl,--no-undefined

FRONT_ENDS := $(IMPL_DIR)/main.c $(IMPL_DIR)/kvmi/kvmi_shell.c $(wildcard $(IMPL_DIR)/*/*_cli.c)
SRCS := $(filter-out $(FRONT_ENDS),$(shell find $(IMPL_DIR) -name '*.c'))
OBJS := $(patsubst $(IMPL_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/bind/%.o: $(BIND_DIR)/%.c $(BIND_DIR)/rv_priv.h $(wildcard $(INTF_DIR)/bind/*.h)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(IMPL_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all clean
