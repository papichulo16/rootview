SRC_DIR := src
BUILD_DIR := build/obj
INTF_DIR := src/intf
IMPL_DIR := src/impl
TARGET := rv

CC := gcc
CFLAGS := -Wall -Wextra -O2 -I$(INTF_DIR) -g $(shell pkg-config --cflags libvmi) 

# have a matching libvmi.so on the loader path anyway.
# -lvirt: vm_qemu.c launches vms through libvirt directly (libvmi's KVMI
# driver resolves domains by name via libvirt, so qemu has to be started
# the same way for the name to resolve).
LDFLAGS := $(shell pkg-config --libs libvmi) -lvirt -Wl,-rpath,'$$ORIGIN'

SRCS := $(shell find $(IMPL_DIR) -name '*.c')
OBJS := $(patsubst $(IMPL_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

all: $(TARGET)

# librootview.so for the python bindings; see bind/Makefile
lib:
	$(MAKE) -C bind

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: $(IMPL_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# leaves the libvmi.so* copied next to rv alone
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
	$(MAKE) -C bind clean


.PHONY: all clean lib
