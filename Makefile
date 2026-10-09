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
	rm -rf $(BUILD_DIR) $(TEST_DIR) $(TARGET)
	$(MAKE) -C bind clean


# offline tests: no libvmi, so only the prof pieces that read through kmem_t
TEST_DIR := build/test
TEST_CFLAGS := -Wall -Wextra -O2 -g -I$(INTF_DIR)
PROF_CORE := $(addprefix $(IMPL_DIR)/kern/prof/,kmem_dump.c pt_root.c pt_walk.c pt_image.c ksym.c btf.c kprof.c kfield.c kwalk.c)
PROF_TESTS := test_pt test_ksym test_btf test_kprof test_kwalk test_kscan test_khash
PROF_SCAN := $(wildcard $(IMPL_DIR)/kern/prof/scan/*.c)
PROF_KHASH := $(wildcard $(IMPL_DIR)/kern/prof/khash/*.c)

test: $(addprefix $(TEST_DIR)/,$(PROF_TESTS))
	./$(TEST_DIR)/test_pt tests/fixtures
	./$(TEST_DIR)/test_ksym tests/fixtures
	./$(TEST_DIR)/test_btf tests/fixtures
	./$(TEST_DIR)/test_kprof tests/fixtures
	./$(TEST_DIR)/test_kwalk tests/fixtures
	./$(TEST_DIR)/test_kscan tests/fixtures
	./$(TEST_DIR)/test_khash tests/fixtures

$(TEST_DIR)/test_%: tests/prof/test_%.c tests/prof/fixture.h $(PROF_CORE)
	mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(TEST_DIR)/test_kscan: tests/prof/test_kscan.c tests/prof/fixture.h $(PROF_CORE) $(PROF_SCAN) $(IMPL_DIR)/kern/prof/scan/kscan_priv.h
	mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(TEST_DIR)/test_khash: tests/prof/test_khash.c tests/prof/fixture.h $(PROF_CORE) $(PROF_KHASH) $(IMPL_DIR)/kern/prof/khash/sha256.h
	mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

.PHONY: all clean lib test
