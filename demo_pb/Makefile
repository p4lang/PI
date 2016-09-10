CXX:= g++
CXXFLAGS:= -O0 -g -Wall --std=c++11
LIBS:=
INCS:=
srcs:=

BUILD_DIR := build/
BUILD_DIRS := $(BUILD_DIR) $(BUILD_DIR)cpp_out $(BUILD_DIR)grpc_out
BUILD_DIRS += cpp_out grpc_out

gen_src = cpp_out/pi.pb.cc grpc_out/pi.grpc.pb.cc
gen_h = cpp_out/pi.pb.h grpc_out/pi.grpc.pb.h

srcs += $(wildcard *.cpp)

INCS += cpp_out grpc_out

CPPFLAGS += $(patsubst %, -I%, $(INCS))

objs := $(patsubst %.cpp, %.o, $(srcs))

deps := $(patsubst %.cpp, %.d, $(srcs))

deps_ := $(patsubst %, $(BUILD_DIR)%, $(deps))
objs_ := $(patsubst %, $(BUILD_DIR)%, $(objs))

all: pi_server test_client app

$(BUILD_DIRS):
	mkdir -p $@

grpc_objs = cpp_out/pi.pb.o grpc_out/pi.grpc.pb.o

$(deps_) $(objs_): $(gen_src) $(gen_h)

$(deps_): $(BUILD_DIR)%.d: %.cpp | $(BUILD_DIRS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MM $< -MT $(BUILD_DIR)$*.o -o $(BUILD_DIR)$*.d

ifeq ($(MAKECMDGOALS),clean)
# doing clean, so dont make deps.
else
# doing build, so make deps.
-include $(deps_)
endif

$(objs_): $(BUILD_DIR)%.o: %.cpp | $(BUILD_DIRS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $(BUILD_DIR)$*.o $<

.proto.ts: pi.proto | $(BUILD_DIRS)
	protoc --grpc_out grpc_out --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` pi.proto
	protoc pi.proto --cpp_out cpp_out

$(gen_src) $(gen_h): .proto.ts
	@touch .proto.ts

grpc_LIBS = `pkg-config --libs grpc++ grpc` -lprotobuf -pthread
bm_LIBS = -lthrift -lruntimestubs -lsimpleswitch_thrift -lnanomsg
pi_LIBS = -lpiall -lpi_bmv2 -lpi_fecpp

pi_server: $(grpc_objs) $(BUILD_DIR)pi_server.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(grpc_LIBS) $(pi_LIBS) $(bm_LIBS)

test_client: $(grpc_objs) $(BUILD_DIR)test_client.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(grpc_LIBS) -lpip4info

app : $(grpc_objs) $(BUILD_DIR)app.o $(BUILD_DIR)simple_router_mgr.o $(BUILD_DIR)web_server.o
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ -lpip4info -lmicrohttpd -lboost_system $(grpc_LIBS)

clean:
	rm -rf $(BUILD_DIRS)
	rm -rf .proto.ts
	rm -f pi_server test_client app

.PHONY: clean
