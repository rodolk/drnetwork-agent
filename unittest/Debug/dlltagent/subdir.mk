################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/rodolk/work/dlltagent/dlltagent/Configuration.cpp \
/home/rodolk/work/dlltagent/dlltagent/Event.cpp \
/home/rodolk/work/dlltagent/dlltagent/FlowsManager.cpp \
/home/rodolk/work/dlltagent/dlltagent/interface.cpp \
/home/rodolk/work/dlltagent/dlltagent/jsoncpp.cpp \
/home/rodolk/work/dlltagent/dlltagent/packetSniffer.cpp \
/home/rodolk/work/dlltagent/dlltagent/processIdentifier.cpp 

OBJS += \
./dlltagent/Configuration.o \
./dlltagent/Event.o \
./dlltagent/FlowsManager.o \
./dlltagent/interface.o \
./dlltagent/jsoncpp.o \
./dlltagent/packetSniffer.o \
./dlltagent/processIdentifier.o 

CPP_DEPS += \
./dlltagent/Configuration.d \
./dlltagent/Event.d \
./dlltagent/FlowsManager.d \
./dlltagent/interface.d \
./dlltagent/jsoncpp.d \
./dlltagent/packetSniffer.d \
./dlltagent/processIdentifier.d 


# Each subdirectory must supply rules for building sources it contributes
dlltagent/Configuration.o: /home/rodolk/work/dlltagent/dlltagent/Configuration.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/Event.o: /home/rodolk/work/dlltagent/dlltagent/Event.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/FlowsManager.o: /home/rodolk/work/dlltagent/dlltagent/FlowsManager.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/interface.o: /home/rodolk/work/dlltagent/dlltagent/interface.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/jsoncpp.o: /home/rodolk/work/dlltagent/dlltagent/jsoncpp.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/packetSniffer.o: /home/rodolk/work/dlltagent/dlltagent/packetSniffer.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/processIdentifier.o: /home/rodolk/work/dlltagent/dlltagent/processIdentifier.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


