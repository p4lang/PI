CC:= gcc
CFLAGS:= -O0 -g -Wall -fPIC
LIBS:=
INCS:=

TARGET:=libpd.so

BUILD_DIR := build/
BUILD_DIRS := $(BUILD_DIR)

srcs:= $(wildcard src/*.c)
INCS += . ../../../include

CFLAGS += $(COMMON_FLAGS)

BUILD_DIRS += $(patsubst %, $(BUILD_DIR)%, $(sort $(dir $(srcs))))

CFLAGS += $(patsubst %, -I%, $(INCS))

objs := $(patsubst %.c, %.o, $(srcs))

deps := $(patsubst %.c, %.d, $(srcs))

deps_ := $(patsubst %, $(BUILD_DIR)%, $(deps))
objs_ := $(patsubst %, $(BUILD_DIR)%, $(objs))

$(TARGET): $(objs_) | $(BUILD_DIRS)
	$(CC) -o $@ $^ -shared

$(BUILD_DIRS):
	mkdir -p $@

$(deps_): $(BUILD_DIR)%.d: %.c | $(BUILD_DIRS)
	$(CC) $(CFLAGS) -MM $< -MT $(BUILD_DIR)$*.o -o $(BUILD_DIR)$*.d

ifeq ($(MAKECMDGOALS),clean)
# doing clean, so dont make deps.
else
# doing build, so make deps.
-include $(deps_)
endif

$(objs_): $(BUILD_DIR)%.o: %.c | $(BUILD_DIRS)
	$(CC) $(CFLAGS) -c -o $(BUILD_DIR)$*.o $<

clean:
	rm -rf $(BUILD_DIRS) $(TARGET)

.PHONY: clean
