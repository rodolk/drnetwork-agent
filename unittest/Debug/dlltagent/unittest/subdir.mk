################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/rodolk/eclipse-workspace/dlltagent/unittest/dlltagentUnitTest.cpp 

OBJS += \
./dlltagent/unittest/dlltagentUnitTest.o 

CPP_DEPS += \
./dlltagent/unittest/dlltagentUnitTest.d 


# Each subdirectory must supply rules for building sources it contributes
dlltagent/unittest/dlltagentUnitTest.o: /home/rodolk/eclipse-workspace/dlltagent/unittest/dlltagentUnitTest.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I/opt/googletest/googletest/include -I"/home/rodolk/eclipse-workspace/dlltagent" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


