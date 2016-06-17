CXX:= g++
CXXFLAGS:= -O0 -g -Wall -fPIC --std=c++11
LIBS:=
INCS:=

TARGET:=libpdthrift.so

BUILD_DIR := build/
BUILD_DIRS := $(BUILD_DIR)

srcs:= $(wildcard thrift-src/*.cpp)
INCS += . gen-cpp

CFLAGS += $(COMMON_FLAGS)

BUILD_DIRS += $(patsubst %, $(BUILD_DIR)%, $(sort $(dir $(srcs))))

CXXFLAGS += $(patsubst %, -I%, $(INCS))

objs := $(patsubst %.cpp, %.o, $(srcs))

deps := $(patsubst %.cpp, %.d, $(srcs))

deps_ := $(patsubst %, $(BUILD_DIR)%, $(deps))
objs_ := $(patsubst %, $(BUILD_DIR)%, $(objs))

$(TARGET): $(objs_) | $(BUILD_DIRS)
	$(CXX) -o $@ $^ -shared

$(BUILD_DIRS):
	mkdir -p $@

$(deps_): $(BUILD_DIR)%.d: %.cpp thrift.ts | $(BUILD_DIRS)
	$(CXX) $(CXXFLAGS) -MM $< -MT $(BUILD_DIR)$*.o -o $(BUILD_DIR)$*.d

ifeq ($(MAKECMDGOALS),clean)
# doing clean, so dont make deps.
else
# doing build, so make deps.
-include $(deps_)
endif

thrift.ts: thrift/p4_pd_rpc.thrift thrift/res.thrift
	thrift --gen cpp thrift/p4_pd_rpc.thrift
	thrift --gen cpp thrift/res.thrift
	mv -f gen-cpp/$(P4_PREFIX).h gen-cpp/p4_prefix.h
	sed --in-place 's/include "$(P4_PREFIX).h"/include "p4_prefix.h"/' gen-cpp/$(P4_PREFIX).cpp
	@touch thrift.ts

$(objs_): $(BUILD_DIR)%.o: %.cpp thrift.ts | $(BUILD_DIRS)
	$(CXX) $(CXXFLAGS) -c -o $(BUILD_DIR)$*.o $<

clean:
	rm -rf $(BUILD_DIRS) $(TARGET) thrift.ts

.PHONY: clean
