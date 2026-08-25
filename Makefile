SRC_DIR := src
BUILD_DIR := build/obj
INTF_DIR := src/intf
IMPL_DIR := src/impl
TARGET := rv

CC := gcc
CFLAGS := -Wall -Wextra -O2 -I$(INTF_DIR) -g $(shell pkg-config --cflags libvmi)

STATIC_VMI_LIBS := $(filter-out -lvirt,$(shell pkg-config --static --libs libvmi))
LIBVIRT_LIBS := -lvirt

SRCS := $(shell find $(IMPL_DIR) -name '*.c')
OBJS := $(patsubst $(IMPL_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -Wl,-Bstatic $(STATIC_VMI_LIBS) -Wl,-Bdynamic $(LIBVIRT_LIBS) -o $@

$(BUILD_DIR)/%.o: $(IMPL_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
