#ifndef HPCAP_H
#define HPCAP_H

#include <WinSock2.h>
#include <Windows.h>
#include <pcap.h>
#include <string>

using namespace std;

extern pcap_if_t* allAdapters; // list of adapters
extern int size; // number of adapters
extern char errbuf[1024]; // number of errors
extern pcap_t* sniff; // sniff
extern struct pcap_pkthdr* packHeader; // the header of packets
extern const u_char* packData; // packets
extern const int packSum; // max loops of packets capture

struct ethernet_info {
    string mac_dest;
    string mac_src;
    string mac_type;
    string mac_content;
};
extern ethernet_info* ethernet_protocal;

struct ip_info {
    string ip_version;
    string ip_headLen;
    string ip_diffserv;
    string ip_totalLen;
    string ip_identification;
    string ip_flag_offset;
    string ip_ttl;
    string ip_protocal;
    string ip_checkSum;
    string ip_src;
    string ip_dest;
    string ip_content[4];
};
extern ip_info* in_protocal;

struct udp_info {
    string udp_sport;
    string udp_dport;
    string udp_len;
    string udp_checkSum;
    string udp_content[2];
};
extern udp_info* udp_protocal;

struct tcp_info {
    string tcp_sport;
    string tcp_dport;
    string tcp_seqNum;
    string tcp_ackNum;
    string tcp_offset_res_flag;
    string tcp_windowSize;
    string tcp_checkSum;
    string tcp_urgentPoint;
    string tcp_content[5];
};
extern tcp_info* tcp_protocal;

bool getAllAdapters(); // 获取网卡信息

bool Sniff(int num);

bool getDataPacket();

bool parseFrame();

bool parseIP();

bool parseTransport(int num);

bool parseTCP();

bool parseUDP();

bool parseICMP();

bool freeAdapters();
#endif // HPCAP_H
