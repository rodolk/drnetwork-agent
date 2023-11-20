/*
 * interface.cpp
 *
 *  Created on: Apr 15, 2021
 *      Author: rodolk
 */

#include <algorithm>
#include "interface.h"

using namespace std;

std::list<Interface> Interface::listInterfaces_;
std::set<Interface> Interface::setInterfaces_;

int Interface::addLocalInterface(string name, string ipAddress) {
    struct sockaddr_in ipSockAddr;

    inet_pton(AF_INET, ipAddress.c_str(), &ipSockAddr.sin_addr);
    ipSockAddr.sin_family = AF_INET;

    Interface intf(name, (sockaddr_storage *)&ipSockAddr);
    listInterfaces_.push_back(intf);
    setInterfaces_.insert(intf);

    return 0;
}

uint32_t Interface::getCorrespondingIP(std::string device) {
    auto iter = std::find_if(listInterfaces_.begin(), listInterfaces_.end(), [&](Interface& intf) {
        return (device == intf.name_);
    });

    if (iter != listInterfaces_.end()) {
        uint32_t ipAddr = (*(struct sockaddr_in *)&iter->sockaddrs_).sin_addr.s_addr;
        return ipAddr;
    } else {
        return 0xFFFFFFFF;
    }
}

int Interface::discoverAllLocalInterfaces(string &internetExposedIPAddress) {
    struct ifaddrs *ifaddr, *ifa;
    int res;
    char host[NI_MAXHOST];
    uint32_t internetExpIP;
    bool intExpExists = false;

    if (getifaddrs(&ifaddr) == -1) {
        cerr << "Error calling getifaddrs" << endl;
        return -1;
    }

    if (internetExposedIPAddress != "") {
        intExpExists = true;
        inet_pton(AF_INET, internetExposedIPAddress.c_str(), &internetExpIP);
    }


    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            res = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (res == 0) {
                bool valueExposed = false;
                if (intExpExists) {
                    if (internetExpIP == (uint32_t)(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr)) {
                        valueExposed = true;
                    }
                }
                Interface intf(ifa->ifa_name, (sockaddr_storage *)ifa->ifa_addr, (sockaddr_storage *)ifa->ifa_netmask, valueExposed);
                listInterfaces_.push_back(intf);
                setInterfaces_.insert(intf);
            } else {
                cerr << "getnameinfo failed for " << ifa->ifa_name << " RES: " << res << endl;
            }
        }
        if (res == EAI_NONAME) return -1;
    }

    freeifaddrs(ifaddr);

    return 0;
}

bool operator<(const Interface& intf1, const Interface& intf2) {
    if (intf1.sockaddrs_.ss_family == AF_INET) return (((sockaddr_in *)&intf1.sockaddrs_)->sin_addr.s_addr < ((sockaddr_in *)&intf2.sockaddrs_)->sin_addr.s_addr);
    else if (intf1.sockaddrs_.ss_family == AF_INET6) {
        return (
                ((sockaddr_in6 *)&intf1.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[0] != ((sockaddr_in6 *)&intf2.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[0] ||
                ((sockaddr_in6 *)&intf1.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[1] != ((sockaddr_in6 *)&intf2.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[1] ||
                ((sockaddr_in6 *)&intf1.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[2] != ((sockaddr_in6 *)&intf2.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[2] ||
                ((sockaddr_in6 *)&intf1.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[3] != ((sockaddr_in6 *)&intf2.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[3]
                );
    }

    return false;
}

