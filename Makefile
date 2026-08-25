SRC_DIR := src
BUILD_DIR := build/obj
INTF_DIR := src/intf
IMPL_DIR := src/impl
TARGET := rv

CC := gcc
CFLAGS := -Wall -Wextra -O2 -I$(INTF_DIR) -g $(shell pkg-config --cflags libvmi) 

# have a matching libvmi.so on the loader path anyway.
LDFLAGS := $(shell pkg-config --libs libvmi) -Wl,-rpath,'$$ORIGIN'

SRCS := $(shell find $(IMPL_DIR) -name '*.c')
OBJS := $(patsubst $(IMPL_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: $(IMPL_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET) *.so*

