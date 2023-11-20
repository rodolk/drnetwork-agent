PROJECT_ROOT = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))../../dlltagent/
BUILD_OUT = $(PROJECT_ROOT)build
TEST_PROJECT_ROOT = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))/../src/


CC = gcc

TEST_SRCS = $(TEST_PROJECT_ROOT)common.cpp $(TEST_PROJECT_ROOT)connectionUnitTest.cpp $(TEST_PROJECT_ROOT)dlltagentUnitTest.cpp \
$(TEST_PROJECT_ROOT)/skbUnitTest.cpp $(TEST_PROJECT_ROOT)/tlsUnitTest.cpp
PROCESS_SRCS = process/processIdentifier.cpp process/processIdentifierLSOF.cpp process/processIdentifierEBPF.cpp
CONNECTORS_SRCS = connectors/RestConnector.cpp connectors/LogfileConnector.cpp
PCAP_SRCS = pcap/PCAPManager.cpp pcap/PCAPDumper.cpp
HTTP_PROCESSING_SRCS = http_processing/HTTPInterpreter.cpp 
TCP_PROCESSING_SRCS = tcp_processing/TLSInterpreter.cpp tcp_processing/TCPSegmentIterator.cpp tcp_processing/frameBuffer.cpp \
tcp_processing/frameStoreHandler.cpp tcp_processing/State.cpp tcp_processing/TLSState.cpp tcp_processing/TLSAlertState.cpp \
tcp_processing/TLSHandshakeState.cpp tcp_processing/TLSFirstState.cpp tcp_processing/TLSApplicationDataState.cpp
MANAGEMENT_SRCS = management/ManagementControl.cpp  management/CloudManagementControl.cpp management/QuestionCommand.cpp management/CommandParser.cpp
SKB_SRCS = skb/skb.cpp skb/binarytree.c
LOG_SRCS = log/daemonLog.cpp log/applicationLog.cpp
FLOWS_SRCS = flows/FlowsManager.cpp flows/StartFlowsManager.cpp flows/EndFlowsManager.cpp flows/FlowProcessManager.cpp
STATIC_LIBS = /usr/lib/x86_64-linux-gnu/libpcap.a /usr/lib/x86_64-linux-gnu/libdbus-1.a

SRCS = packetSniffer.cpp  jsoncpp.cpp Configuration.cpp \
interface.cpp \
$(CONNECTORS_SRCS) $(PCAP_SRCS) $(TCP_PROCESSING_SRCS) $(HTTP_PROCESSING_SRCS) $(MANAGEMENT_SRCS) $(SKB_SRCS) $(LOG_SRCS) $(PROCESS_SRCS) $(FLOWS_SRCS)

TARGET_OBJS = $(addprefix $(BUILD_OUT)/, $(notdir $(patsubst %.cpp, %.o, $(filter %.cpp, $(SRCS))) $(patsubst %.c, %.o, $(filter %.c, $(SRCS)))))
TEST_OBJS = $(notdir $(patsubst %.cpp, %.o, $(filter %.cpp, $(TEST_SRCS))))

DIRS = $(sort $(dir $(SRCS)))
INCLUDE_MKS = $(filter-out $(PROJECT_ROOT)./makeinc.mk, $(patsubst %, $(PROJECT_ROOT)%makeinc.mk, $(DIRS)))

LIBS = -lgtest -lgtest_main -lpthread -ldl -lsystemd

INCLUDE = -I$(TEST_PROJECT_ROOT) -I$(PROJECT_ROOT)thirdparty/include -I$(PROJECT_ROOT)common \
-I$(PROJECT_ROOT)plugins -I$(PROJECT_ROOT)ebpf $(foreach dir,$(DIRS),-I$(PROJECT_ROOT)$(dir))

#CFLAGS += -g -DGDB_SRV
#CPPFLAGS += -g -DGDB_SRV -std=c++17
CPPFLAGS += -std=c++17 -g -Wall -Werror -DUNIT_TEST
#-Wl,--unresolved-symbols=ignore-in-object-files
CFLAGS += -g -Wall -Werror
#ifeq ($(BUILD_MODE),debug)
#	CFLAGS += -g
#else ifeq ($(BUILD_MODE),run)
#	CFLAGS += -O2
#else
#	$(error Build mode $(BUILD_MODE) not supported by this Makefile)
#endif

export PROJECT_ROOT BUILD_OUT TEST_PROJECT_ROOT

all: dlltagent unittest


.PHONY: clean dlltagent unittest

dlltagent:
	make -C $(BUILD_OUT) ADDENV="-DUNIT_TEST"

unittest: $(TEST_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CXX) $(CPPFLAGS) -o "dlltagentUnitTest" $^ $(TARGET_OBJS) $(STATIC_LIBS) -L/opt/googletest/build/lib $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

%.o: $(TEST_PROJECT_ROOT)%.cpp
	$(CXX) -c $(CPPFLAGS) $(INCLUDE) -o $@ $<


clean:
	rm *.o
	rm dlltagentUnitTest
	make clean -C $(BUILD_OUT)
	