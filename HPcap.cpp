#include "HPcap.h"

pcap_if_t* allAdapters = nullptr; // list of adapters
int size = 0; // number of adapters
char errbuf[1024]; // number of errors
pcap_t* sniff = nullptr; // sniff
struct pcap_pkthdr* packHeader = nullptr; // the header of packets
const u_char* packData = nullptr; // packets
const int packSum = -1; // max loops of packets capture
ethernet_info* ethernet_protocal = nullptr;
ip_info* ip_protocal = nullptr;
udp_info* udp_protocal = nullptr;
tcp_info* tcp_protocal = nullptr;

bool getAllAdapters() {
    return true;
}

bool Sniff() {
    return true;
}

bool getDataPacket() {
    return true;
}

bool parseFrame() {
    return true;
}

bool parseIP() {
    return true;
}

bool parseTransport(int num) {
    return true;
}

bool parseTCP() {
    return true;
}

bool parseUDP() {
    return true;
}

bool parseICMP() {
    return true;
}

bool freeAdapters() {
    pcap_freealldevs(allAdapters);
    return true;
}
