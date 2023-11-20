#PROJECT_ROOT and BUILD_OUT from environment

CC = gcc 

LOG_SRCS = log/daemonLog.cpp log/daemon_log.cpp

SRCS = $(LOG_SRCS)

OBJS = $(notdir $(patsubst %.cpp, %.o, $(filter %.cpp, $(SRCS))) $(patsubst %.c, %.o, $(filter %.c, $(SRCS))))

DIRS = $(sort $(dir $(SRCS)))

LIBS = -lpthread
#-lssl -lcrypto -ldl -lm -lz 

INCLUDE = -I$(PROJECT_ROOT)common

#CFLAGS += -g -DGDB_SRV
#CPPFLAGS += -g -DGDB_SRV -std=c++17
CPPFLAGS += -std=c++17 -g -Wall -Werror -fPIC 
#-DCURL_STATICLIB
#-Wl,--unresolved-symbols=ignore-in-object-files

CFLAGS += -g -Wall -Werror
#-DCURL_STATICLIB

#ifeq ($(BUILD_MODE),debug)
#	CFLAGS += -g
#else ifeq ($(BUILD_MODE),run)
#	CFLAGS += -O2
#else
#	$(error Build mode $(BUILD_MODE) not supported by this Makefile)
#endif

all: libdlltlog.so


libdlltlog.so: $(OBJS)
	echo $(CXX)
	$(CXX) -shared -o $@ $^ $(LIBS)

%.o:	$(PROJECT_ROOT)log/%.cpp
	$(CXX) -c $(CPPFLAGS) $(INCLUDE) -o $@ $<
	
%.o:	$(PROJECT_ROOT)%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) -o $@ $<

clean:
	rm -fr libdlltlog.so $(OBJS)
