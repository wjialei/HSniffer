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
extern const u_char* packData; // packets
extern vector<const u_char*> packDataVec;
extern const int packSum; // max loops of packets capture


struct ethernet_info {
    string mac_dest;
    string mac_src;
    string mac_type;
    string mac_content;
};
extern ethernet_info* ethernet_protocol;
extern vector<ethernet_info*> ethernetProtocolVec;

struct arp_info {
    u_short arp_htype;
    u_short arp_ptype;
    u_char arp_hsize;
    u_char arp_psize;
    u_short arp_opcode;
    u_char arp_src[6];
    u_char arp_sip[4];
    u_char arp_dest[6];
    u_char arp_dip[4];
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
extern ip_info* ip_protocol;
extern vector<ip_info*> ipProtocolVec;

struct udp_info {
    string udp_sport;
    string udp_dport;
    string udp_len;
    string udp_checkSum;
    string udp_content[2];
};
extern udp_info* udp_protocol;
extern vector<udp_info*> udpProtocolVec;

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
extern tcp_info* tcp_protocol;
extern vector<tcp_info*> tcpProtocolVec;

struct data_packet {
    char packet_type[8];
    int time[6];
    int len;

    ethernet_info* ethernet_header;
    arp_info* arp_header;
    ip_info* ip_header;

    tcp_info* tcp_header;
    udp_info* udp_header;
};
extern vector<data_packet*> dataPacketVec;

bool getAllAdapters(); // 获取网卡信息

bool Sniff(int num);

bool getDataPacket();
bool captureDataPacket(pcap_pkthdr*, const u_char*);

bool parseFrame();
bool parseEthernetProtocol(data_packet*, const u_char*);

bool parseIP();
bool parseNetworkProtocol(data_packet*, const u_char*);


bool parseTransport(int num);
bool parseTransportProtocol(data_packet*, const u_char*);

bool parseTCP();
bool parseTcpProtocol(data_packet*, const u_char*);

bool parseUDP();
bool parseUdpProtocol(data_packet*, const u_char*);

bool parseICMP();
bool parseIcmpProtocol(data_packet*, const u_char*);

bool freeAdapters();
#endif // HPCAP_H
