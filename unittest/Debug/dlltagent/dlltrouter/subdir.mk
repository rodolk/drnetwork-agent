################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/rodolk/work/dlltagent/dlltagent/dlltrouter/Router.cpp \
/home/rodolk/work/dlltagent/dlltagent/dlltrouter/dlltrouter.cpp 

CPP_DEPS += \
./dlltagent/dlltrouter/Router.d \
./dlltagent/dlltrouter/dlltrouter.d 

OBJS += \
./dlltagent/dlltrouter/Router.o \
./dlltagent/dlltrouter/dlltrouter.o 


# Each subdirectory must supply rules for building sources it contributes
dlltagent/dlltrouter/Router.o: /home/rodolk/work/dlltagent/dlltagent/dlltrouter/Router.cpp dlltagent/dlltrouter/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

dlltagent/dlltrouter/dlltrouter.o: /home/rodolk/work/dlltagent/dlltagent/dlltrouter/dlltrouter.cpp dlltagent/dlltrouter/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -I"/home/rodolk/work/dlltagent/dlltagent/process" -I"/home/rodolk/work/dlltagent/dlltagent/ebpf" -I"/home/rodolk/work/dlltagent/dlltagent/http_processing" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-dlltagent-2f-dlltrouter

clean-dlltagent-2f-dlltrouter:
	-$(RM) ./dlltagent/dlltrouter/Router.d ./dlltagent/dlltrouter/Router.o ./dlltagent/dlltrouter/dlltrouter.d ./dlltagent/dlltrouter/dlltrouter.o

.PHONY: clean-dlltagent-2f-dlltrouter

