KERNEL_ROOT=/home/rodolk/work/bpfinc/usr/src/focal

#       gcc -Wp,-MD,.processConnectEBPF.o.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I$(KERNEL_ROOT)/usr/include -I$(KERNEL_ROOT)/tools/lib/ -DHAVE_ATTR_TEST=0  -c -o processConnectEBPF.o processConnectEBPF.c
#       gcc -Wp,-MD,.processConnectEBPF.d -Wall -O2 -DHAVE_ATTR_TEST=0   -o processConnectEBPF processConnectEBPF.o $(KERNEL_ROOT)/tools/lib/bpf/libbpf.a -lelf -lz

#PROJECT_ROOT and BUILD_OUT from environment

CC = gcc

EBPF_SRCS = ebpf/processConnectEBPF.c
LOG_SRCS = log/daemonLog.cpp log/daemon_log.cpp

SRCS = $(EBPF_SRCS) $(LOG_SRCS)

OBJS = $(notdir $(patsubst %.cpp, %.o, $(filter %.cpp, $(SRCS))) $(patsubst %.c, %.o, $(filter %.c, $(SRCS))))

DIRS = $(sort $(dir $(SRCS)))

#LIBS = $(KERNEL_ROOT)/tools/lib/bpf/libbpf.a -lelf -lz
LIBS = -L$(KERNEL_ROOT)/tools/lib/bpf -lbpf -lelf -lz

INCLUDE = -I$(KERNEL_ROOT)/usr/include -I$(KERNEL_ROOT)/tools/lib/ -I$(PROJECT_ROOT)log -I$(PROJECT_ROOT)common

CFLAGS += -Wp,-MD,.processConnectEBPF.o.d -g -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -Werror -fPIC -DHAVE_ATTR_TEST=0
#CPPFLAGS += -g -DGDB_SRV -std=c++17
CPPFLAGS += -std=c++17 -g -Wall -Werror -fPIC
#-DCURL_STATICLIB
#-Wl,--unresolved-symbols=ignore-in-object-files


#ifeq ($(BUILD_MODE),debug)
#       CFLAGS += -g
#else ifeq ($(BUILD_MODE),run)
#       CFLAGS += -O2
#else
#       $(error Build mode $(BUILD_MODE) not supported by this Makefile)
#endif

all: libdlltebpf.so


libdlltebpf.so: $(OBJS)
	echo $(CXX)
	$(CXX) -shared -o $@ $^ $(LIBS)

#%.o:   $(PROJECT_ROOT)plugins/%.cpp
#       $(CXX) -c $(CPPFLAGS) $(INCLUDE) -o $@ $<

%.o:    $(PROJECT_ROOT)ebpf/%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) -o $@ $<

include $(PROJECT_ROOT)log/makeinc.mk

clean:
	rm -fr libdlltebpf.so $(OBJS)

