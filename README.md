# drnetwork-agent
DrNetwork DLLTAgent to discover connectivity, performance and security issues in distributed applications.

This agent can detect network problems and application connectivity problems in 1 sec.
There are certain types of distributed applications issues that are very difficult to discover without network protocols knowledge.
DrNetwork agent has this knowledge embedded as heuristics.

This is WIP and might not be easy to build at the beginning, but I'll slowly make it easier :)

So far, I tested DLLTAgent running in AWS images and Ubuntu distributions 20.04 and 22.04. 

It can work with EKS and Cilium.

You can read file instructions.txt in https://github.com/rodolk/dlltagent_tools to get more information.
https://github.com/rodolk/dlltagent_tools/blob/master/instructions.txt

This file is more focused on using this code in a pod for torubleshooting in Kubernetes environment: EKS.
The code in this repository can be used also without Kubernetes.

## Building drnetwork dlltagent

To build, go to folder **dlltagent/build** and run `make`.
The code has some dependencies:

- libpcap.a: **Makefile** expects to find it in **/usr/lib/x86_64-linux-gnu/libpcap.a**
- libdbus-1.a: **Makefile** expects to find it in **/usr/lib/x86_64-linux-gnu/libdbus-1.a**
- libsystemd.so
- libdl.so
- libpthread.so

### REST plugin
The REST plugin is **libdlltrestconnector.so** and it is built in folder **plugins**:
It has dependencies on:

- libbcurl.so
- libpthread.so

### LOG library
For logging we generate library **libdlltlog.so** in **build/log**.
The only dependecy is:

- libpthread.so

### EBPF for process connections
DLLTAgent can use EBPF to detect the process generating a connection and the user running that process.
For this, it needs to link library **libdlltebpf.so** that will install the proper EBPF module and will communicate with it.
This is created in folder **build/ebpf**
The code for the EBPF module can be found in https://github.com/rodolk/ebpf_process_connect
We are going to use only the kernel module in that repository.

Note this dynamic library requires:

- libbpf.so: it expects to find it in $(KERNEL_ROOT)/tools/lib/bpf and you'll need to install this library in the same directory as libdlltebpf.so is found.
- libelf.so
- libz.so

You have to install BPF: 
$(KERNEL_ROOT)/tools/lib/bpf

Define **KERNEL_ROOT** in **build/ebpf/Makefile**. Change the current value before building.





rodolk

rodolfo.kohn@wayaga.com



