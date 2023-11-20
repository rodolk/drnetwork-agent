
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fstream>
#include <signal.h>

#include <string>
#include <thread>
#include <map>
#include <cstdlib>

#include "daemonLog.h"
#include "applicationLog.h"
#include "packetSniffer.h"
#include "RestConnector.h"
#include "LogfileConnector.h"
#include "PCAPManager.h"
#include "CloudManagementControl.h"
#include "ManagementControl.h"
#include "interface.h"
#include "json/json.h"
#include "Configuration.h"
#include "processIdentifierLSOF.h"
#include "processIdentifierEBPF.h"
#include "env.h"
#include "FlowProcessManager.h"

#define LOG_FILENAME "log_notif"
#define DEFAULT_CONFIG_FILE "/etc/dllt/dllt.cfg"
#define PATH_ENV_VAR "LD_LIBRARY_PATH"


DaemonLog *daemonLogging{nullptr};
PacketSniffer *packetSniffer;
bool serverRunning = false;



static void int_exit(int sig) {
    if (daemonLogging) {
        daemonLogging->warning("Signal received: agent winding down, please be patient\n");
    }
    packetSniffer->endSniffing();
    if (daemonLogging) {
        daemonLogging->warning("Agent shutdown initiated\n");
    }
}

int initServer(DaemonLog::eLOGLevel logLevel, bool _foregroundExec, string& configFileString)
{
    int error = 0;
    int res;
    char myc[10000];
    std::thread *threadSnifferAgent;
    char myc2[10000];
    std::thread *threadManagementControl;
    char myc3[10000];
    char logFile[200];
    // http://localhost:7690/dllt/connection
//    string resource = "api/v1/networkevents/new";
//    string resource = "netevt/_doc";

    bzero(myc, 10000);
    bzero(myc2, 10000);
    bzero(myc3, 10000);
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);


    //First read configuration. Then e open log file for write. We need logs directory
    Configuration::initialize();
    Configuration& config = Configuration::getInstance();

    config.setConfiguredValues(configFileString);

    cout << "Logs directory: " << config.logsDirectory << endl;

    daemonLogging = new DaemonLog();
    if (!_foregroundExec) {
        sprintf(logFile,"%s", LOG_FILENAME);
        daemonLogging->initialize(config.logsDirectory.c_str(), logFile);
    } else {
        daemonLogging->initialize();
    }
    daemonLogging->setLogLevel(logLevel);

    ApplicationLog::setLog(daemonLogging);


    if(const char* env_p = std::getenv(SEARCH_HTTP_HEADER)) {
        daemonLogging->info("%s env var value: %s\n", SEARCH_HTTP_HEADER, env_p);
        gEnvVarsMap[SEARCH_HTTP_HEADER] = env_p;
    }
    if(const char* env_p = std::getenv(FOLLOW_PORT)) {
        char *auxPtr;
        daemonLogging->info("%s env var value: %s\n", FOLLOW_PORT, env_p);
        gEnvVarsMap[FOLLOW_PORT] = env_p;

        gFollowPort = strtol(env_p, &auxPtr, 10);
        if (gFollowPort == 0) {
            if (!(*auxPtr == 0 && errno == 0)) {
                daemonLogging->error("Error in port value set in env var %s: %s\n", FOLLOW_PORT, env_p);
            } else {
                daemonLogging->info("Env var %s is set to 0. No port following.\n", FOLLOW_PORT, env_p);
            }
        } else {
            daemonLogging->info("Following port %d\n", gFollowPort);
        }
    }

    if(const char* env_p = std::getenv(AVOID_LIVENESS_PROBE)) {
        daemonLogging->info("%s env var value: %s\n", AVOID_LIVENESS_PROBE, env_p);
        auto envFound = gEnvVarsMap.find(SEARCH_HTTP_HEADER);
        if (envFound != gEnvVarsMap.end()) {
            if (strcmp(env_p, envFound->second.c_str()) == 0) {
                daemonLogging->warning("CANNOT Avoid same header we are searching. Dropping avoid option.\n");
            } else {
                gEnvVarsMap[AVOID_LIVENESS_PROBE] = env_p;
            }
        } else {
            gEnvVarsMap[AVOID_LIVENESS_PROBE] = env_p;
        }
    } else {
        daemonLogging->info("%s env var not found\n", AVOID_LIVENESS_PROBE);
    }

    daemonLogging->info("Domain name: %s\n", config.domainName.c_str());
    daemonLogging->info("Port: %d\n", config.servicePort);
    daemonLogging->info("pcap filter: %s\n", config.pcapFilter.c_str());
    daemonLogging->info("pcap device: %s\n", config.pcapDevice.c_str());
    daemonLogging->info("Local ip address: %s\n", config.locaIPAddress.c_str());
    daemonLogging->info("tls: %s\n", config.tlsOption ? "true":"false");
    daemonLogging->info("tls, ignore server cert: %s\n", config.tlsIgnoreSrvCertOption ? "true":"false");
    daemonLogging->info("eBPF enabled: %s\n", config.ebpfOption ? "true":"false");
    daemonLogging->info("Deployment type: %s\n", config.deploymentTypeString.c_str());
    daemonLogging->info("Logs directory: %s\n", config.logsDirectory.c_str());

    if (config.locaIPAddress == "") {
        res = Interface::discoverAllLocalInterfaces(config.internetExposedIPAddress);
        if (res != 0) {
            daemonLogging->error("Error discovering interfaces\n");
        }
    } else {
        Interface::addLocalInterface(config.pcapDevice, config.locaIPAddress);
    }
    Interface::printAll();

    uint32_t addrLocalIf = Interface::getCorrespondingIP(config.pcapDevice);
    daemonLogging->info("Local IP addr for device %s: %X\n", config.pcapDevice.c_str(), addrLocalIf);

    std::list<uint32_t> ipBackSvcList = Interface::getIPAddrFromServiceName(config.domainName);
    PCAPManager *pcapMgr = new PCAPManager(daemonLogging);
    packetSniffer = new PacketSniffer();
    connectors::Connector *connector = nullptr;
    connectors::RestConnector *restConnector = nullptr;
    management::ManagementControl *managementControl = nullptr;
    ProcessIdentifier *pConnIdentifier = nullptr;
    ProcessIdentifier *pListenIdentifier = nullptr;
    flows::FlowProcessManager *flowProcessManager = nullptr;

    serverRunning = true;

    if (config.ebpfOption) {
        daemonLogging->info("Using EBPF\n");
        flowProcessManager = new flows::FlowProcessManager();
        flowProcessManager->init();
        pConnIdentifier = new ProcessIdentifierEBPF(*flowProcessManager, addrLocalIf);
        int res = pConnIdentifier->initialize();
        if (res != 0) {
            cerr << "Error initializing ProcessIdentifierEBPF - Code: " << res << " - Error string: " <<  ((ProcessIdentifierEBPF *)pConnIdentifier)->getErrorString() << endl;
            daemonLogging->error("Error initializing ProcessIdentifierEBPF - Code: %d - Error string: %s\n", res, ((ProcessIdentifierEBPF *)pConnIdentifier)->getErrorString().c_str());
            error = 1;
        } else {
            daemonLogging->info("Connecting ProcessIdentifierEBPF correctly initialized\n");
        }
        pListenIdentifier = new ProcessIdentifierLSOF();
        res = pListenIdentifier->initialize();
        if (res != 0) {
            cerr << "Error initializing Listening ProcessIdentifierLSOF - Code: " << res << endl;
            daemonLogging->error("Error initializing Listening ProcessIdentifierLSOF - Code: %d\n", res);
            error = 1;
        } else {
            daemonLogging->info("Listening ProcessIdentifierLSOF correctly initialized\n");
        }
    } else {
        pConnIdentifier = new ProcessIdentifierLSOF();
        if (pConnIdentifier->initialize() == -2) {
            delete pConnIdentifier;
            pConnIdentifier = new ProcessIdentifier();
            pConnIdentifier->initialize();
        }
        pListenIdentifier = new ProcessIdentifierLSOF();
        if (pListenIdentifier->initialize() == -2) {
            delete pListenIdentifier;
            pListenIdentifier = new ProcessIdentifier();
            pListenIdentifier->initialize();
        }
    }

    if (error == 0) {
        switch(config.deploymentType) {
        case Configuration::DEPLOYMENT_CLOUD:
            restConnector = new connectors::RestConnector();
            connector = restConnector;
            try {
                restConnector->initialize();
                managementControl = new management::CloudManagementControl(*packetSniffer, *restConnector);
            } catch(connectors::RestConnector::ConnectorException& e) {
                cerr << "Error initializing Cloud ManagementControl - Code: " << e.getCode() << " - Error: " << e.getMsg() << endl;
                daemonLogging->error("Error initializing Cloud ManagementControl - Code: %u - Error: %s", e.getCode(), e.getMsg().c_str());
                error = 1;
            }
            break;
        case Configuration::DEPLOYMENT_LOCAL:
            connector = new connectors::LogfileConnector();
            managementControl = new management::ManagementControl(*packetSniffer);
            break;
        case Configuration::DEPLOYMENT_LOCALBACKEND:
            restConnector = new connectors::RestConnector();
            connector = restConnector;
            try {
                restConnector->initialize();
                managementControl = new management::ManagementControl(*packetSniffer);
            } catch(connectors::RestConnector::ConnectorException& e) {
                cerr << "Error initializing ManagementControl - Code: " << e.getCode() << " - Error: " << e.getMsg() << endl;
                daemonLogging->error("Error initializing ManagementControl - Code: %u - Error: %s", e.getCode(), e.getMsg().c_str());
                error = 1;
            }
            break;
        default:
            cerr << "Critical configuration error: deployment type: " << config.deploymentTypeString << " - does not exist." << endl;
            daemonLogging->error("Critical configuration error: deployment type: %s  - does not exist.", config.deploymentTypeString.c_str());
            error = 1;
            break;
        }
    }

    if (0 == error) {
        packetSniffer->initialize(*connector, *pcapMgr, *daemonLogging, config.pcapFilter, config.pcapDevice, ipBackSvcList, pConnIdentifier, pListenIdentifier, flowProcessManager);
        threadSnifferAgent = new std::thread(PacketSniffer::runAgentThread, packetSniffer);
        threadManagementControl = new std::thread(management::ManagementControl::managementControllerThr, managementControl);
        daemonLogging->info("JOIN SNIFFER AGENT THR\n");
        threadSnifferAgent->join();
        daemonLogging->info("FINISHED SNIFFER AGENT\n");
        managementControl->setEnd();
        threadManagementControl->join();
        daemonLogging->info("FINISHED THREAD MANAGEMENT CONTROL\n");

        delete threadSnifferAgent;
        delete threadManagementControl;
    }

    daemonLogging->info("************************* FINISHING AGENT *************************\n");
    if (pListenIdentifier != nullptr) delete pListenIdentifier;
    if (pConnIdentifier != nullptr) delete pConnIdentifier;
    delete pcapMgr;
    if (connector != nullptr) delete connector;
    delete packetSniffer;

    if (flowProcessManager != nullptr) delete flowProcessManager;

    serverRunning = false;

    return error;
}

int createDaemon()
{
    /* Our process ID and Session ID */
    pid_t pid, sid;
    // int val;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0)
    {
        exit(-1);
    }
    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0)
    {
        exit(0);
    }

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
    {
        /* Log the failure */
        exit(-2);
    }

    /* Change the file mode mask */
    umask(0);

    /* Change the current working directory */
/*    if ((chdir("/home/ec2-user/server")) < 0)
    {
        exit(-3);
    }
*/
    /* Close out the standard file descriptors */
/*    close(1);
    close(2);

    val = open("/home/ec2-user/server/sever1.daemonLogging", O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    if (val < 0)
    {
        exit(-errno);
    }

    close(0); */
    /* Daemon-specific initialization goes here */
    return 0;
}



DaemonLog::eLOGLevel getLogLevel(char logLevelInitial)
{

    switch(logLevelInitial)
    {
        case 'e':
            return DaemonLog::LOGLevelError;
        case 'w':
            return DaemonLog::LOGLevelWarning;
        case 'i':
            return DaemonLog::LOGLevelInfo;
        case 'v':
            return DaemonLog::LOGLevelInfoVerbose;
        case 'd':
            return DaemonLog::LOGLevelDebug;
    }

    return (DaemonLog::eLOGLevel)-1;
}

static void printUsage(string& cmd) {
    cout << "dlltagent is a tool that detects problems in a distributed application based on network traffic." << endl;
    cout << "Please look carefully at the configuration file since there are various options that can be helpful" << endl;
    cout << "It generates 3 types of files: " << endl;
    cout << "  -events files: with all events in json format." << endl;
    cout << "  -flows files: with all flows in text format." << endl;
    cout << "  -pcap files: files in pcap format for connections for which a possible problem was detected. These files can be open with wireshark" << endl;
    cout << "Usage:" << endl;
    cout << cmd << " [-f] [-l e|w|i|v|d] [-c <config file>]" << endl;
    cout << "-c    Configuration file  | default: " << DEFAULT_CONFIG_FILE << endl;
    cout << "-l    Log level           | default: " << DaemonLog::LOGLevelInfo << " (i)" << endl;
    cout << "-d    Run as daemon       | default: foreground" << endl;
    cout << endl;
}

/*
 * -f: foreground
 * -l: loglevel (e, w, i, v, d)
*/
int main(int argc, char *argv[])
{
    string cmd = argv[0];
    int iMode = 1;
    int opt;
    DaemonLog::eLOGLevel logLevel = DaemonLog::LOGLevelInfo;
    string configFileString = DEFAULT_CONFIG_FILE;

    cout << "DLLT Agent executing ..." << endl;

    while ((opt = getopt(argc, argv, "hdl:c:")) != -1)
    {
        switch (opt) {
        case 'd':
            iMode = 0;
            break;
        case 'l':
            logLevel = getLogLevel(optarg[0]);
            break;
        case 'c':
            configFileString = optarg;
            break;
        case 'h':
            printUsage(cmd);
            exit(0);
        default: /* '?' */
            printUsage(cmd);
            exit(-1);
        }
    }

    cout << "Configuration file: " << configFileString << endl;
    cout << "It'd better be there. If not ..." << endl;

    ifstream configFile(configFileString);
    if (configFile.fail()) {
        cerr << "Couldn't open " << configFileString << ". Does it exist? Did you lie to me?" << endl;
        printUsage(cmd);
        exit(-1);
    } else {
        cout << "It's there. OK." << endl;
    }
    configFile.close();

    if (logLevel < DaemonLog::LOGLevelError || logLevel > DaemonLog::LOGLevelDebug)
    {
        cerr << "Wrong log level" << endl;
        printUsage(cmd);
        exit(-1);
    }

    cout << "Log level: " << logLevel << endl;

    if (iMode == 0)
    {
        cout << "Running as daemon" << endl;
        createDaemon();
    } else {
        cout << "Running as foreground" << endl;
    }

    cout << endl;

    initServer(logLevel, (iMode == 1) ? true : false, configFileString);

    return 0;
}
