# drnetwork-agent
DrNetwork DLLTAgent to discover connectivity, performance and security issues in distributed applications.

This agent can detect network problems and application connectivity problems in 1 sec.
There are certain types of distributed application issues that are very difficult to discover without network protocol knowledge.
DrNetwork agent has this knowledge embedded as heuristics.

This is WIP and might not be easy to build at the beginning, but I'll slowly make it easier :)

So far, I tested it in AWS images and Ubuntu images. 

It can work with EKS and Cilium.

You can read file instructions.txt in https://github.com/rodolk/dlltagent_tools to get more information.
https://github.com/rodolk/dlltagent_tools/blob/master/instructions.txt

This file is more focused on using this code in a pod for torubleshooting in Kubernetes environment: EKS.
The code in this repository can be used also without Kubernetes.

rodolk
rodolfo.kohn@wayaga.com



