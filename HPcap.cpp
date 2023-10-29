#include <HPcap.h>

#include <iostream>

// 用于保存信息的宏
#define FUN(S, N) string(N - S.size(), '0') + S
#define MY_NTOHS(x) ((((x) >> 8) & 0xFF) | (((x) & 0xFF) << 8))
#define MY_NTOHL(x) ((((x) >> 24) & 0xFF) | (((x >> 8) & 0xFF) << 8) | (((x >> 16) & 0xFF) << 16) | ((x & 0xFF) << 24))

pcap_if_t* allAdapters = nullptr; // list of adapters
int cntAdapters = 0; // number of adapters
char errbuf[SIZE]; // number of errors
pcap_t* sniff = nullptr; // sniff
struct pcap_pkthdr* packHeader; // the header of packets
vector<pcap_pkthdr*> packHeaderVec;
const u_char* packData; // packets
vector<const u_char*> rawDataVec;
vector<data_packet*> dataPacketVec;
const char* filter_exp;

struct bpf_program fp;		/* The compiled filter expression */
bpf_u_int32 mask;		/* The netmask of our sniffing device */
bpf_u_int32 net;		/* The IP of our sniffing device */


// itoa 封装，转为指定进制的string 类型
char buf[SIZE/ 2];
template <class T>
string dataToString(T data,int radix) {
    memset(buf,0x00,sizeof buf);
    itoa(data,buf,radix);
    return buf;
}

// 点分十进制
string iptos(long in)
{
    u_char *p;
    p = (u_char *)&in;
    memset(buf, 0x00, sizeof buf);
    sprintf(buf, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return buf;
}

bool getAllAdapters() {

    if(allAdapters) {
        freeAdapters();
        cntAdapters = 0;
    }
    allAdapters = nullptr;
    memset(errbuf, 0x00, sizeof(errbuf));
    int ret = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &allAdapters, errbuf);
    if (ret == -1)
    {
        return false;
    }
    pcap_if_t *ptr = allAdapters;
    while(ptr) {
        ptr = ptr->next;
        cntAdapters++;
    }
    return true;
}

bool Sniff(int num, string filter_pattern) {
    if(num < 0) return false;
    pcap_if_t* adapter = allAdapters;
    for(int i=0; i<num-1&&adapter; i++) {
        adapter = adapter->next;
    }
    if(adapter == nullptr) return false;
    const char* dev = adapter->name;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
             cout << "get netmask flase" << endl;
             net = 0;
             mask = 0;
    }
    sniff = pcap_open(adapter->name, MAXDATAFRAME, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf);
    if(sniff == nullptr) {
        return false;
    }
    filter_exp = filter_pattern.c_str();
    if(pcap_compile(sniff, &fp, filter_exp, 0, net) == -1) {
        cout << "filter compile false" << endl;
        return false;
    }
    if (pcap_setfilter(sniff, &fp) == -1) {
        cout << "filter set false" << endl;
        return false;
    }
    if(pcap_datalink(sniff) != DLT_EN10MB) return false;
    return sniff!=nullptr;
}

bool getDataPacket() {
    packData = nullptr;
    int r= pcap_next_ex(sniff, &packHeader, &packData);
    return r;
}

bool parseEthernetProtocol(data_packet* dp, const u_char* d) {
    struct ethernet_header {
        u_char ether_dhost[6];
        u_char ether_shost[6];
        u_short ether_type;
    };
    ethernet_header* etherH = (ethernet_header*)d;

    dp->ethernet_header = new ethernet_info();
#define NTOHS(A) ((((A)&0xFF00)>>8) | (((A)&0x00FF)<<8));
    etherH->ether_type = NTOHS(etherH->ether_type);
    dp->ethernet_header->mac_type = "0x" + dataToString(etherH->ether_type, 16);

    // dest mac address
    memset(buf, 0x00, sizeof (buf));
    sprintf(buf, " %02X:%02X:%02X:%02X:%02X:%02X ",
            etherH->ether_dhost[0],
            etherH->ether_dhost[1],
            etherH->ether_dhost[2],
            etherH->ether_dhost[3],
            etherH->ether_dhost[4],
            etherH->ether_dhost[5]);
    dp->ethernet_header->mac_dest = buf;

    // source mac address
    memset(buf, 0x00, sizeof (buf));
    sprintf(buf, " %02X:%02X:%02X:%02X:%02X:%02X ",
            etherH->ether_shost[0],
            etherH->ether_shost[1],
            etherH->ether_shost[2],
            etherH->ether_shost[3],
            etherH->ether_shost[4],
            etherH->ether_shost[5]);
    dp->ethernet_header->mac_src = buf;

    dp->ethernet_header->mac_content += "0x";
    for(int i=0; i<6; i++) {
        string s = dataToString(etherH->ether_dhost[i], 16);
        dp->ethernet_header->mac_content += string("0", 2-s.size()) + s + " ";
    }
    for(int i=0; i<6; i++) {
        string s = dataToString(etherH->ether_shost[i], 16);
        dp->ethernet_header->mac_content += string("0", 2-s.size()) + s + " ";
    }
    string s = dataToString(etherH->ether_type, 16);
    dp->ethernet_header->mac_content += string("0", 4-s.size()) + s;

    return true;
}

bool parseNetworkProtocol(data_packet* dp, const u_char* d) {
    struct ip_header {
        u_char ip_version_headerLen;
        u_char ip_service;
        u_short ip_totalLen;
        u_short ip_identification;
        u_short ip_flag_offset;
        u_char ip_ttl;
        u_char ip_protocol;
        u_short ip_checkSum;
        long ip_src;
        long ip_dest;
    };
    ip_header* ipH = (ip_header*)(d + 14);

    dp->ip_header = new ip_info();
    if((ipH->ip_version_headerLen&(0x40)) == 0x40) {
        dp->ip_header->ip_version = "ipv4";
    } else if((ipH->ip_version_headerLen&(0x60)) == 0x60) {
        dp->ip_header->ip_version = "ipv6";
    } else {
        return false;
    }
    char len = ipH->ip_version_headerLen & 0x0f;
    if(len < 0x05) return false;
    dp->ip_header->ip_headLen = "0x" + dataToString(len, 16);
    dp->ip_header->ip_diffserv = "0x" + dataToString(ipH->ip_service, 16);
    dp->ip_header->ip_totalLen = "0x" + dataToString(MY_NTOHS(ipH->ip_totalLen), 16);
    dp->ip_header->ip_identification = "0x" + dataToString(MY_NTOHS(ipH->ip_identification), 16);
    dp->ip_header->ip_flag_offset = "0x" + dataToString(MY_NTOHS(ipH->ip_flag_offset), 16);
    dp->ip_header->ip_ttl = "0x" + dataToString(ipH->ip_ttl, 16);
    dp->ip_header->ip_protocol = dataToString(ipH->ip_protocol, 10);
    dp->ip_header->ip_checkSum = "0x" + dataToString(ipH->ip_checkSum, 16);
    dp->ip_header->ip_src = iptos(ipH->ip_src);
    dp->ip_header->ip_dest = iptos(ipH->ip_dest);
    dp->ip_header->ip_content[0] = "0x" + FUN(dataToString(ipH->ip_version_headerLen,16),2) + " " + FUN(dataToString(ipH->ip_service,16),2) + " " + FUN(dataToString(ipH->ip_totalLen,16),4);
    dp->ip_header->ip_content[1] = "0x" + FUN(dataToString(ipH->ip_identification,16),4) + " " + FUN(dataToString(ipH->ip_flag_offset,16),4);
    dp->ip_header->ip_content[2] = "0x" + FUN(dataToString(ipH->ip_ttl,16),2) + " " + FUN(dataToString(ipH->ip_protocol,16),2) + " " + FUN(dataToString(ipH->ip_checkSum,16),4);

    return true;
}

bool parseTcpProtocol(data_packet* dp, const u_char* d) {
    struct tcp_header {
        u_short tcp_sport;
        u_short tcp_dport;
        u_int tcp_seqNum;
        u_int tcp_ackNum;
        u_short tcp_off_res_flag;
        u_short tcp_winSize;
        u_short tcp_checkSum;
        u_short tcp_urgentPoint;
    };
    tcp_header* tcpH = (tcp_header*)(d + 14 + 20);

    dp->tcp_header = new tcp_info();
    dp->tcp_header->tcp_sport = "0x" + dataToString(MY_NTOHS(tcpH->tcp_sport), 16)+ "(" + to_string(MY_NTOHS(tcpH->tcp_sport)) + ")";
    dp->tcp_header->tcp_dport = "0x" + dataToString(MY_NTOHS(tcpH->tcp_dport), 16) + "(" + to_string(MY_NTOHS(tcpH->tcp_dport)) + ")";
    dp->tcp_header->tcp_seqNum = "0x" + dataToString(MY_NTOHL(tcpH->tcp_seqNum), 16) + "(" + to_string(MY_NTOHL(tcpH->tcp_seqNum)) + ")";
    dp->tcp_header->tcp_ackNum = "0x" + dataToString(MY_NTOHS(tcpH->tcp_ackNum), 16) + "(" + to_string(MY_NTOHS(tcpH->tcp_ackNum)) + ")";
    dp->tcp_header->tcp_offset_res_flag = "0x" + dataToString(MY_NTOHS(tcpH->tcp_off_res_flag), 16);
    dp->tcp_header->tcp_windowSize = "0x" + dataToString(MY_NTOHS(tcpH->tcp_winSize), 16);
    dp->tcp_header->tcp_checkSum = "0x" + dataToString(MY_NTOHS(tcpH->tcp_checkSum), 16);
    dp->tcp_header->tcp_urgentPoint = "0x" + dataToString(MY_NTOHS(tcpH->tcp_urgentPoint), 16);
    dp->tcp_header->tcp_content[0] = "0x" + FUN(dataToString(MY_NTOHS(tcpH->tcp_sport), 16), 4) + " " + FUN(dataToString(MY_NTOHS(tcpH->tcp_dport), 16), 4);
    dp->tcp_header->tcp_content[1] = "0x" + FUN(dataToString(MY_NTOHL(tcpH->tcp_seqNum), 16), 8);
    dp->tcp_header->tcp_content[2] = "0x" + FUN(dataToString(MY_NTOHL(tcpH->tcp_ackNum), 16), 8);
    dp->tcp_header->tcp_content[3] = "0x" + FUN(dataToString(MY_NTOHS(tcpH->tcp_off_res_flag), 16), 4) + " " + FUN(dataToString(MY_NTOHS(tcpH->tcp_winSize), 16), 4);
    dp->tcp_header->tcp_content[4] = "0x" + FUN(dataToString(MY_NTOHS(tcpH->tcp_checkSum), 16), 4) + " " + FUN(dataToString(MY_NTOHS(tcpH->tcp_urgentPoint), 16), 4);

    return true;
}

bool parseUdpProtocol(data_packet* dp, const u_char* d) {
    struct udp_header {
        u_short udp_sport;
        u_short udp_dport;
        u_short udp_length;
        u_short udp_checkSum;
    };
    udp_header* udpH = (udp_header*)(d + 14 + 20);

    dp->udp_header = new udp_info();
    dp->udp_header->udp_sport = "0x" + dataToString(udpH->udp_sport,16) + "(" + to_string(udpH->udp_sport) + ")";
    dp->udp_header->udp_dport = "0x" +dataToString(udpH->udp_dport,16) + "(" + to_string(udpH->udp_dport) + ")";
    dp->udp_header->udp_len = "0x" +dataToString(udpH->udp_length,16);
    dp->udp_header->udp_checkSum = "0x" +dataToString(udpH->udp_checkSum,16);
    dp->udp_header->udp_content[0] = "0x" + FUN(dataToString(udpH->udp_sport, 16), 4) + " " + FUN(dataToString(udpH->udp_dport, 16), 4);
    dp->udp_header->udp_content[1] = "0x" + FUN(dataToString(udpH->udp_length, 16), 4) + " " + FUN(dataToString(udpH->udp_checkSum, 16), 4);

    return true;
}

bool parseArpProtocol(data_packet* dp, const u_char* d) {
    struct arp_header {
        u_short arp_htype;
        u_short arp_ptype;
        u_char arp_hsize;
        u_char arp_psize;
        u_short arp_opcode;
        u_char arp_src[6];
        long arp_sip;
        u_char arp_dest[6];
        long arp_dip;
    };
    arp_header* arpH = (arp_header*)(d + 14);

    dp->arp_header = new arp_info();
    dp->arp_header->arp_htype = "0x" + dataToString(MY_NTOHS(arpH->arp_htype), 16);
    dp->arp_header->arp_ptype = "0x" + dataToString(MY_NTOHS(arpH->arp_ptype), 16);
    dp->arp_header->arp_hsize = "0x" + dataToString(arpH->arp_hsize, 16);
    dp->arp_header->arp_psize = "0x" + dataToString(arpH->arp_psize, 16);
    dp->arp_header->arp_opcode = "0x" + dataToString(MY_NTOHS(arpH->arp_opcode), 16);
    dp->arp_header->arp_sip = iptos(arpH->arp_sip);
    dp->arp_header->arp_dip = iptos(arpH->arp_dip);

    // dest mac address
    memset(buf, 0x00, sizeof (buf));
    sprintf(buf, " %02X:%02X:%02X:%02X:%02X:%02X ",
            arpH->arp_dest[0],
            arpH->arp_dest[1],
            arpH->arp_dest[2],
            arpH->arp_dest[3],
            arpH->arp_dest[4],
            arpH->arp_dest[5]);
    dp->arp_header->arp_dest = buf;

    // source mac address
    memset(buf, 0x00, sizeof (buf));
    sprintf(buf, " %02X:%02X:%02X:%02X:%02X:%02X ",
            arpH->arp_src[0],
            arpH->arp_src[1],
            arpH->arp_src[2],
            arpH->arp_src[3],
            arpH->arp_src[4],
            arpH->arp_src[5]);
    dp->arp_header->arp_src = buf;

    return true;
}

bool parseIcmpProtocol(data_packet* dp, const u_char* d) {
    struct icmp_header {
        u_char icmp_type;
        u_char icmp_code;
        u_short icmp_checkSum;
        u_short icmp_identification;
        u_short icmp_seq;
        u_int icmp_initTime;
        u_short icmp_recvTime;
        u_short icmp_sendTime;
    };
    icmp_header* icmpH = (icmp_header*)(d + 14 +20);

    dp->icmp_header = new icmp_info();
    dp->icmp_header->icmp_type = "0x" + dataToString(icmpH->icmp_type, 16);
    dp->icmp_header->icmp_code = "0x" + dataToString(icmpH->icmp_code, 16);
    dp->icmp_header->icmp_checkSum = "0x" + dataToString(MY_NTOHS(icmpH->icmp_checkSum), 16);
    dp->icmp_header->icmp_identification = "0x" + dataToString(MY_NTOHS(icmpH->icmp_identification), 16);
    dp->icmp_header->icmp_seq = "0x" + dataToString(MY_NTOHS(icmpH->icmp_seq), 16);
    dp->icmp_header->icmp_initTime = "0x" + dataToString(MY_NTOHL(icmpH->icmp_initTime), 16);
    dp->icmp_header->icmp_recvTime = "0x" + dataToString(MY_NTOHS(icmpH->icmp_recvTime), 16);
    dp->icmp_header->icmp_sendTime = "0x" + dataToString(MY_NTOHS(icmpH->icmp_sendTime), 16);

    return true;
}

bool freeAdapters() {
    pcap_freealldevs(allAdapters);
    return true;
}

string getProtocol(data_packet* dp) {
    if(dp->ethernet_header->mac_type == "0x800") {
        switch(atoi(dp->ip_header->ip_protocol.c_str())) {
        case 1:
            // icmp
            return "ICMP";
            break;
        case 6:
            // tcp
            return "TCP";
            break;
        case 17:
            // udp
            return "UDP";
            break;
        }
    } else if(dp->ethernet_header->mac_type == "0x806") {
        // arp
        return "ARP";

    } else if(dp->ethernet_header->mac_type == "0x86dd"){
        // ipv6
        return "IPv6";
    }
    return "unknown";

}
