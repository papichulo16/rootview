# librootview.so: the engine plus bind/rootview.c's flat api, for the python
# bindings (src/ui/dynamic/rootview_web/backends/rvlib.py). built from the same
# ../src/impl sources as rv, minus the command-line front ends (main.c, the
# *_cli.c files and kvmi_shell.c), into a separate -fPIC object tree.
# lands next to rv so the same $ORIGIN rpath finds the libvmi.so copied there.
# only the rv_* functions are exported.

ROOT := ..
IMPL_DIR := $(ROOT)/src/impl
INTF_DIR := $(ROOT)/src/intf
BUILD_DIR := $(ROOT)/build/pic
TARGET := $(ROOT)/librootview.so

CC := gcc
CFLAGS := -Wall -Wextra -O2 -g -fPIC -fvisibility=hidden -I$(INTF_DIR) -I. $(shell pkg-config --cflags libvmi)
LDFLAGS := -shared $(shell pkg-config --libs libvmi) -lvirt -Wl,-rpath,'$$ORIGIN' -Wl,--no-undefined

FRONT_ENDS := $(IMPL_DIR)/main.c $(IMPL_DIR)/kvmi/kvmi_shell.c $(wildcard $(IMPL_DIR)/*/*_cli.c)
SRCS := $(filter-out $(FRONT_ENDS),$(shell find $(IMPL_DIR) -name '*.c'))
OBJS := $(patsubst $(IMPL_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS)) $(BUILD_DIR)/bind/rootview.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/bind/rootview.o: rootview.c rootview.h
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(IMPL_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all clean
