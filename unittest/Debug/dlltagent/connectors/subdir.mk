################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/rodolk/work/dlltagent/dlltagent/connectors/LogfileConnector.cpp \
/home/rodolk/work/dlltagent/dlltagent/connectors/RestConnector.cpp 

CPP_DEPS += \
./dlltagent/connectors/LogfileConnector.d \
./dlltagent/connectors/RestConnector.d 

OBJS += \
./dlltagent/connectors/LogfileConnector.o \
./dlltagent/connectors/RestConnector.o 


# Each subdirectory must supply rules for building sources it contributes
dlltagent/connectors/LogfileConnector.o: /home/rodolk/work/dlltagent/dlltagent/connectors/LogfileConnector.cpp dlltagent/connectors/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -I"/home/rodolk/work/dlltagent/dlltagent/flows" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/connectors/RestConnector.o: /home/rodolk/work/dlltagent/dlltagent/connectors/RestConnector.cpp dlltagent/connectors/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -I"/home/rodolk/work/dlltagent/dlltagent/flows" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-dlltagent-2f-connectors

clean-dlltagent-2f-connectors:
	-$(RM) ./dlltagent/connectors/LogfileConnector.d ./dlltagent/connectors/LogfileConnector.o ./dlltagent/connectors/RestConnector.d ./dlltagent/connectors/RestConnector.o

.PHONY: clean-dlltagent-2f-connectors

