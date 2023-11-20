################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/rodolk/work/dlltagent/dlltagent/http_processing/HTTPInterpreter.cpp 

CPP_DEPS += \
./dlltagent/http_processing/HTTPInterpreter.d 

OBJS += \
./dlltagent/http_processing/HTTPInterpreter.o 


# Each subdirectory must supply rules for building sources it contributes
dlltagent/http_processing/HTTPInterpreter.o: /home/rodolk/work/dlltagent/dlltagent/http_processing/HTTPInterpreter.cpp dlltagent/http_processing/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -I"/home/rodolk/work/dlltagent/dlltagent/flows" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-dlltagent-2f-http_processing

clean-dlltagent-2f-http_processing:
	-$(RM) ./dlltagent/http_processing/HTTPInterpreter.d ./dlltagent/http_processing/HTTPInterpreter.o

.PHONY: clean-dlltagent-2f-http_processing

