/*
 * Configuration.h
 *
 *  Created on: Jun 8, 2021
 *      Author: rodolk
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <string>
#include <cstdint>
#include <fstream>
#include <list>

#include "json/json.h"

#define DEFAULT_AGENT_ID "910139d0-b17b-4838-86f1-34391a6d085b"
#define DEPLOYMENT_CLOUD_STR "cloud"
#define DEPLOYMENT_LOCAL_STR "local_nobackend"
#define DEPLOYMENT_LOCAL_BACKEND_STR "local_backend"
#define RESOURCE_NAME "Prod/networkevent/_bulk"
#define RESOURCE_NAME_LOCALBACKEND "api/v1/networkevent/_bulk"
#define DEFAULT_SERVICE_DOMAIN_NAME "127.0.0.1"
#define DEFAULT_SERVICE_PORT 8080
#define DEFAULT_PCAP_FILTER "tcp"
#define DEFAULT_PCAP_DEVICE "enp0s3"
#define DEFAULT_LOCAL_IP_ADDRESS ""
#define DEFAULT_LOGS_DIRECTORY "."
#define PATH_DELIM ":"



#define LIB_PATH_DEFAULT "."

using namespace std;

class Configuration {
public:
    enum DeploymentType_t {DEPLOYMENT_LOCAL, DEPLOYMENT_LOCALBACKEND, DEPLOYMENT_CLOUD};
    string agentID;
    string domainName;
    uint16_t servicePort;
    string questionResource;
    string responseResource;
    string eventResource;
    bool tlsOption;
    bool tlsIgnoreSrvCertOption;
    uint16_t keepaliveThresholdStaleEstablished{0};
    uint16_t keepaliveThresholdEstablishedKilled{0};
    DeploymentType_t deploymentType;
    string deploymentTypeString;
    bool events_for_tls_connections;
    bool NoHTTPSClientSSLShutdownEvent; //Do not send event for HTTPS client SSLShutdown before TLS Application Data State.
    bool NoHTTPClientResetEvent; //Do not send event for HTTPS client sending Reset
    string pcapFilter;
    string pcapDevice;
    bool ebpfOption;
    string libPathString;
    string ebpfObjectPath;
    list<string> libPathList;
    string logsDirectory;
    string locaIPAddress;
    bool incomingInternetConnections;
    string internetExposedIPAddress;
    bool eventStaleSSHFromInternet;

    static void initialize() {
        instance_ = new Configuration();
    }

    static Configuration& getInstance() {return *instance_;}

    void setConfiguredValues(const string& configFileString) {
        Json::Value configJson;

        std::ifstream configFile(configFileString);
        configFile >> configJson;

        domainName = configJson.get("service_domain_name", DEFAULT_SERVICE_DOMAIN_NAME).asString();
        servicePort = (uint16_t)configJson.get("service_port", DEFAULT_SERVICE_PORT).asUInt();
        pcapFilter = configJson.get("pcap_filter", DEFAULT_PCAP_FILTER).asString();
        pcapDevice = configJson.get("pcap_device", DEFAULT_PCAP_DEVICE).asString();
        locaIPAddress = configJson.get("local_ip_address", DEFAULT_LOCAL_IP_ADDRESS).asString();
        tlsOption = configJson.get("tls", false).asBool();
        tlsIgnoreSrvCertOption = configJson.get("tls_ignore_server_certificate", false).asBool();
        agentID = configJson.get("agent_id", DEFAULT_AGENT_ID).asString();

        responseResource = "Prod/facts/" + agentID + "/_bulk";
        questionResource = "Prod/facts/" + agentID + "/questions";

        events_for_tls_connections = configJson.get("events_for_tls_connections", true).asBool();

        deploymentTypeString = configJson.get("deployment_type", DEPLOYMENT_CLOUD_STR).asString();
        deploymentType = (deploymentTypeString == DEPLOYMENT_LOCAL_STR) ? Configuration::DEPLOYMENT_LOCAL :
                (deploymentTypeString == DEPLOYMENT_LOCAL_BACKEND_STR) ?  Configuration::DEPLOYMENT_LOCALBACKEND : Configuration::DEPLOYMENT_CLOUD;

        if (deploymentType == Configuration::DEPLOYMENT_LOCALBACKEND) {
            eventResource = RESOURCE_NAME_LOCALBACKEND;
        } else {
            eventResource = RESOURCE_NAME;
        }

        NoHTTPSClientSSLShutdownEvent = configJson.get("no_event_https_client_ssl_shutdown", true).asBool();
        NoHTTPClientResetEvent = configJson.get("no_event_http_client_reset", true).asBool();

        ebpfOption = configJson.get("ebpf", false).asBool();
        libPathString = configJson.get("libpath", LIB_PATH_DEFAULT).asString();
        ebpfObjectPath = configJson.get("ebpf_object_path", ".").asString();
        logsDirectory = configJson.get("logs_directory", DEFAULT_LOGS_DIRECTORY).asString();
        incomingInternetConnections = configJson.get("incoming_internet_connections", true).asBool();
        internetExposedIPAddress = configJson.get("internet_ip_address", "").asString();
        eventStaleSSHFromInternet = configJson.get("event_stale_ssh", false).asBool();
        parseLibPath();

        configFile.close();
    }

private:
    static Configuration *instance_;

    Configuration();
    virtual ~Configuration();

    void parseLibPath() {
        std::string delim = PATH_DELIM;

        auto start = 0U;
        auto end = libPathString.find(delim);
        while (end != std::string::npos)
        {
            libPathList.push_back(libPathString.substr(start, end - start));
            start = end + delim.length();
            end = libPathString.find(delim, start);
        }

        libPathList.push_back(libPathString.substr(start));
    }

};

#endif /* CONFIGURATION_H_ */
