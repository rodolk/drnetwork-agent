#PROJECT_ROOT and BUILD_OUT from environment

CC = gcc 

CONNECTOR_PLUGINS_SRCS = plugins/RestPlugin.cpp
#MANAGEMENT_SRCS = management/ManagementControl.cpp management/CloudManagementControl.cpp management/QuestionCommand.cpp management/CommandParser.cpp
#MANAGEMENT_SRCS = management/ManagementControl.cpp management/QuestionCommand.cpp management/CommandParser.cpp
#STATIC_CURL = -Wl,-Bstatic -lcurl -Wl,-Bdynamic -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -lnghttp2 -lidn2 -lrtmp -lpsl -lssl -lcrypto -lssl -lcrypto -llber -lldap -llber -lz 
#/usr/lib/x86_64-linux-gnu/libcurl.a /usr/lib/x86_64-linux-gnu/libz.a /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a
#STATIC_LIBS = /usr/lib/x86_64-linux-gnu/libpcap.a

SRCS = $(CONNECTOR_PLUGINS_SRCS)

OBJS = $(notdir $(patsubst %.cpp, %.o, $(filter %.cpp, $(SRCS))) $(patsubst %.c, %.o, $(filter %.c, $(SRCS))))

DIRS = $(sort $(dir $(SRCS)))

LIBS = -lcurl -lpthread
#-lssl -lcrypto -ldl -lm -lz 

INCLUDE = -I$(PROJECT_ROOT)connectors -I$(PROJECT_ROOT) -I$(PROJECT_ROOT)log -I$(PROJECT_ROOT)common

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

all: libdlltrestconnector.so


libdlltrestconnector.so: $(OBJS)
	echo $(CXX)
	$(CXX) -shared -o $@ $^ $(LIBS)

%.o:	$(PROJECT_ROOT)plugins/%.cpp
	$(CXX) -c $(CPPFLAGS) $(INCLUDE) -o $@ $<
	
%.o:	$(PROJECT_ROOT)%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) -o $@ $<

clean:
	rm -fr libdlltrestconnector.so $(OBJS)
