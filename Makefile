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

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: $(IMPL_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TEST_DIR) $(TARGET) *.so*


# offline tests: no libvmi, so only the prof pieces that read through kmem_t
TEST_DIR := build/test
TEST_CFLAGS := -Wall -Wextra -O2 -g -I$(INTF_DIR)
PROF_CORE := $(IMPL_DIR)/kern/prof/kmem_dump.c $(IMPL_DIR)/kern/prof/pt_root.c $(IMPL_DIR)/kern/prof/pt_walk.c

test: $(TEST_DIR)/test_pt
	./$(TEST_DIR)/test_pt tests/fixtures

$(TEST_DIR)/test_pt: tests/prof/test_pt.c $(PROF_CORE)
	mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $^ -o $@

.PHONY: all clean test
