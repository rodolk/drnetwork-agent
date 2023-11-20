################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/common.cpp \
../src/connectionUnitTest.cpp \
../src/dlltagentUnitTest.cpp \
../src/skbUnitTest.cpp \
../src/tlsUnitTest.cpp 

OBJS += \
./src/common.o \
./src/connectionUnitTest.o \
./src/dlltagentUnitTest.o \
./src/skbUnitTest.o \
./src/tlsUnitTest.o 

CPP_DEPS += \
./src/common.d \
./src/connectionUnitTest.d \
./src/dlltagentUnitTest.d \
./src/skbUnitTest.d \
./src/tlsUnitTest.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++17 -I/opt/googletest/googletest/include -I"/home/rodolk/work/dlltagent/dlltagent/common" -I"/home/rodolk/work/dlltagent/dlltagent/log" -I"/home/rodolk/work/dlltagent/dlltagent/pcap" -I"/home/rodolk/work/dlltagent/dlltagent/skb" -I"/home/rodolk/work/dlltagent/dlltagent/tcp_processing" -I"/home/rodolk/work/dlltagent/dlltagent/thirdparty/include" -I"/home/rodolk/work/dlltagent/dlltagent" -I"/home/rodolk/work/dlltagent/dlltagent/management" -I"/home/rodolk/work/dlltagent/dlltagent/connectors" -I"/home/rodolk/work/dlltagent/dlltagent/plugins" -O0 -g3 -Wall -c -fmessage-length=0  -DUNIT_TEST -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


