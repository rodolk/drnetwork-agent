/*
 * interface.h
 *
 *  Created on: Apr 15, 2021
 *      Author: rodolk
 */

#ifndef INTERFACE_H_
#define INTERFACE_H_

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>

#include <iostream>
#include <list>
#include <set>
#include <cstring>

#include "applicationLog.h"

using namespace std;

class Interface {
public:
    string name_;
    sockaddr_storage sockaddrs_;
    sockaddr_storage netmask_;
    bool hasNetmask_;
    bool internetExposed_{true}; //By default all true

    static int discoverAllLocalInterfaces(string &internetExposedIPAddress);

    static int addLocalInterface(string name, string ipAddress);

    Interface(const std::string& name, const sockaddr_storage *sockaddrs, const sockaddr_storage *netmask, bool exposed) : name_(name) {
        memcpy(&sockaddrs_, sockaddrs, sizeof(sockaddr_storage));
        if (netmask) {
            memcpy(&netmask_, netmask, sizeof(sockaddr_storage));
            hasNetmask_ = true;
        } else {
            hasNetmask_ = false;
        }
        internetExposed_ = exposed;
    }
    Interface(const std::string& name, const sockaddr_storage *sockaddrs) : name_(name) {
        memcpy(&sockaddrs_, sockaddrs, sizeof(sockaddr_storage));
        hasNetmask_ = false;
        internetExposed_ = false;
    }
    virtual ~Interface() {}

/*
    bool operator<(const Interface& intf) {
        if (sockaddrs_.ss_family == AF_INET) return (((sockaddr_in *)&sockaddrs_)->sin_addr.s_addr < ((sockaddr_in *)&intf.sockaddrs_)->sin_addr.s_addr);
        else if (sockaddrs_.ss_family == AF_INET6) {
            return (
                    ((sockaddr_in6 *)&sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[0] != ((sockaddr_in6 *)&intf.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[0] ||
                    ((sockaddr_in6 *)&sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[1] != ((sockaddr_in6 *)&intf.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[1] ||
                    ((sockaddr_in6 *)&sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[2] != ((sockaddr_in6 *)&intf.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[2] ||
                    ((sockaddr_in6 *)&sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[3] != ((sockaddr_in6 *)&intf.sockaddrs_)->sin6_addr.__in6_u.__u6_addr32[3]
                    );
        }

        return false;
    }
*/
    friend bool operator<(const Interface& intf1, const Interface& intf2);

    static uint32_t getCorrespondingIP(std::string device);

    static bool isLocal(const Interface& intf) {
        std::set<Interface>::iterator iter = setInterfaces_.find(intf);
        if (iter != setInterfaces_.end()){
            return true;
        } else {
            return false;
        }
    }

    static bool isLocal(uint32_t ipAddr) {
        union {
            sockaddr_storage sockaddrs;
            sockaddr_in addr_in;
        } addrIf;
        addrIf.addr_in.sin_family = AF_INET;
        addrIf.addr_in.sin_addr.s_addr = ipAddr;

        Interface intf("", &addrIf.sockaddrs);

        std::set<Interface>::iterator iter = setInterfaces_.find(intf);
        if (iter != setInterfaces_.end()) {
            return true;
        } else {
            return false;
        }
    }

    static bool isLocalNetwork(uint32_t ipAddr) {
        for(Interface& intf : listInterfaces_) {
            uint32_t valueMasked1 = (((sockaddr_in *)&intf.sockaddrs_)->sin_addr.s_addr) & (((sockaddr_in *)&intf.netmask_)->sin_addr.s_addr);
            if (intf.hasNetmask_) {
                uint32_t valueMasked2 = ipAddr & (((sockaddr_in *)&intf.netmask_)->sin_addr.s_addr);
                //TODO: check for subnet cases
                if (valueMasked1 == valueMasked2) {
                    return true;
                }
            }
        }
        return false;
    }

    /*
     * If Dest IP is a local address and it's exposed, then the connection may come from the Internet.
     * We check the network mask for determining that.
     * TODO: add check for subnet
     */
    static bool isFromInternet(uint32_t ipAddrSrc, uint32_t ipAddrDest) {
        for(Interface& intf : listInterfaces_) {
            if ((((sockaddr_in *)&intf.sockaddrs_)->sin_addr.s_addr) == ipAddrDest) {
                if (intf.internetExposed_) {
                    if (intf.hasNetmask_) {
                        uint32_t valueMasked1 = (((sockaddr_in *)&intf.sockaddrs_)->sin_addr.s_addr) & (((sockaddr_in *)&intf.netmask_)->sin_addr.s_addr);
                        uint32_t valueMasked2 = ipAddrSrc & (((sockaddr_in *)&intf.netmask_)->sin_addr.s_addr);
                        //TODO: check for subnet cases
                        if (valueMasked1 == valueMasked2) {
                            return false;
                        } else {
                            return true;
                        }
                    } else {
                        //TODO: error
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
        //TODO: Error
        return false;
    }

    static void printAll() {
        for(Interface& intf : listInterfaces_) {
            std::cout << intf.name_ << ", ";
            if (intf.sockaddrs_.ss_family == AF_INET) {
                uint8_t *byte = (uint8_t *)&(((sockaddr_in *)&intf.sockaddrs_)->sin_addr.s_addr);
                std::cout <<  (unsigned int)byte[0] << "." << (unsigned int)byte[1] << "." << (unsigned int)byte[2] << "." << (unsigned int)byte[3] << ", ";
                if (intf.hasNetmask_) {
                    byte = (uint8_t *)&(((sockaddr_in *)&intf.netmask_)->sin_addr.s_addr);
                    std::cout <<  (unsigned int)byte[0] << "." << (unsigned int)byte[1] << "." << (unsigned int)byte[2] << "." << (unsigned int)byte[3] << std::endl;
                } else {
                    std::cout << "netmask is NULL" << std::endl;
                }
            } else {
                std::cout << "Not IPv4" << std::endl;
            }
        }
    }

    static list<uint32_t> getIPAddrFromServiceName(string domainName) {
        struct addrinfo hints;
        struct addrinfo *results = nullptr;
        struct addrinfo *rp = nullptr;
        int res;
        list<uint32_t> ipaddrList;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_flags = 0;
        hints.ai_protocol = 0;
        hints.ai_socktype = SOCK_STREAM;

        res = getaddrinfo(domainName.c_str(), NULL, &hints, &results);
        if (res != 0) {
            cout << "Error calling getaddrinfo with domain name: " << domainName << endl;
        } else {
            for(rp = results; rp != NULL; rp = rp->ai_next) {
                uint32_t addr = ((struct sockaddr_in *)rp->ai_addr)->sin_addr.s_addr;
                uint8_t *ptr = (uint8_t *)&addr;
                ApplicationLog::getLog().info("IP addr for %s: %3d.%3d.%3d.%3d\n", domainName.c_str(), ptr[0], ptr[1], ptr[2], ptr[3]);
                ipaddrList.push_back(addr);
            }
        }
        if (results != nullptr) freeaddrinfo(results);
        return ipaddrList;
    }


private:
    static std::list<Interface> listInterfaces_;
    static std::set<Interface> setInterfaces_;

};


#endif /* INTERFACE_H_ */
