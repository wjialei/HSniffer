#ifndef HPCAP_H
#define HPCAP_H

#include <WinSock2.h>
#include <Windows.h>
#include <pcap.h>
#include <string>
#include <vector>

using namespace std;
#define SIZE 1024
#define  MAXDATAFRAME 1518
extern pcap_if_t* allAdapters; // list of adapters
extern int cntAdapters; // number of adapters
extern char errbuf[SIZE]; // number of errors
extern pcap_t* sniff; // sniff
extern struct pcap_pkthdr* packHeader; // the header of packets
extern vector<pcap_pkthdr*> packHeaderVec;
extern const u_char* packData; // packets
extern vector<const u_char*> rawDataVec;
extern const char* filter_exp;

struct ethernet_info {
    string mac_dest;
    string mac_src;
    string mac_type;
    string mac_content;
};

struct arp_info {
    string arp_htype;
    string arp_ptype;
    string arp_hsize;
    string arp_psize;
    string arp_opcode;
    string arp_src;
    string arp_sip;
    string arp_dest;
    string arp_dip;
};

struct ip_info {
    string ip_version;
    string ip_headLen;
    string ip_diffserv;
    string ip_totalLen;
    string ip_identification;
    string ip_flag_offset;
    string ip_ttl;
    string ip_protocol;
    string ip_checkSum;
    string ip_src;
    string ip_dest;
    string ip_content[4];
};

struct udp_info {
    string udp_sport;
    string udp_dport;
    string udp_len;
    string udp_checkSum;
    string udp_content[2];
};

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

struct icmp_info {
    string icmp_type;
    string icmp_code;
    string icmp_checkSum;
    string icmp_identification;
    string icmp_seq;
    string icmp_initTime;
    string icmp_recvTime;
    string icmp_sendTime;
};

struct data_packet {
    char packet_type[8];
    int time[6];
    int len;

    ethernet_info* ethernet_header;
    arp_info* arp_header;
    ip_info* ip_header;

    tcp_info* tcp_header;
    udp_info* udp_header;
    icmp_info* icmp_header;
};
extern vector<data_packet*> dataPacketVec;

bool getAllAdapters(); // 获取网卡信息

bool Sniff(int, string);

bool getDataPacket();

bool parseEthernetProtocol(data_packet*, const u_char*);

bool parseArpProtocol(data_packet*, const u_char*);

bool parseNetworkProtocol(data_packet*, const u_char*);

bool parseTcpProtocol(data_packet*, const u_char*);

bool parseUdpProtocol(data_packet*, const u_char*);

bool parseIcmpProtocol(data_packet*, const u_char*);

bool freeAdapters();

string getProtocol(data_packet*);
#endif // HPCAP_H
