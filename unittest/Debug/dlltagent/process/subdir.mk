################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/rodolk/work/dlltagent/dlltagent/process/processIdentifier.cpp \
/home/rodolk/work/dlltagent/dlltagent/process/processIdentifierEBPF.cpp \
/home/rodolk/work/dlltagent/dlltagent/process/processIdentifierLSOF.cpp 

CPP_DEPS += \
./dlltagent/process/processIdentifier.d \
./dlltagent/process/processIdentifierEBPF.d \
./dlltagent/process/processIdentifierLSOF.d 

OBJS += \
./dlltagent/process/processIdentifier.o \
./dlltagent/process/processIdentifierEBPF.o \
./dlltagent/process/processIdentifierLSOF.o 


# Each subdirectory must supply rules for building sources it contributes
dlltagent/process/processIdentifier.o: /home/rodolk/work/dlltagent/dlltagent/process/processIdentifier.cpp dlltagent/process/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -I"/home/rodolk/work/dlltagent/dlltagent/flows" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/process/processIdentifierEBPF.o: /home/rodolk/work/dlltagent/dlltagent/process/processIdentifierEBPF.cpp dlltagent/process/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -I"/home/rodolk/work/dlltagent/dlltagent/flows" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/process/processIdentifierLSOF.o: /home/rodolk/work/dlltagent/dlltagent/process/processIdentifierLSOF.cpp dlltagent/process/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -I"/home/rodolk/work/dlltagent/dlltagent/flows" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-dlltagent-2f-process

clean-dlltagent-2f-process:
	-$(RM) ./dlltagent/process/processIdentifier.d ./dlltagent/process/processIdentifier.o ./dlltagent/process/processIdentifierEBPF.d ./dlltagent/process/processIdentifierEBPF.o ./dlltagent/process/processIdentifierLSOF.d ./dlltagent/process/processIdentifierLSOF.o

.PHONY: clean-dlltagent-2f-process

