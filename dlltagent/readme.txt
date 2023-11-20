
How to execute:
sudo LD_LIBRARY_PATH=~/work/dllt_test/lib ./dlltagent -l
With env variable to find connection:
sudo LD_LIBRARY_PATH=~/work/dllt_test/lib SEARCH_HTTP_HEADER=X-Pepe ./dlltagent -ld

Required libraries:
*libcurl4-openssl-dev
  sudo apt-get install libcurl4-openssl-dev

*libelf-dev
  sudo apt install libelf-dev

*libpcap-dev
  sudo apt install libpcap-dev

*libsystemd
  sudo apt install -y libsystemd-dev

*libdbus
  For pcap
  
*jsoncpp
https://github.com/open-source-parsers/jsoncpp
https://chromium.googlesource.com/external/github.com/open-source-parsers/jsoncpp/+/refs/heads/0.y.z/README.md


*bpfinc is required
/home/rodolk/work/bpfinc/usr/src/focal

