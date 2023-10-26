#include <HPcap.h>

#include <iostream>

pcap_if_t* allAdapters = nullptr; // list of adapters
int cntAdapters = 0; // number of adapters
char errbuf[SIZE]; // number of errors
pcap_t* sniff = nullptr; // sniff
struct pcap_pkthdr* packHeader; // the header of packets
const u_char* packData; // packets
vector<const u_char*> packDataVec;
const int packSum = 100; // max loops of packets capture
ethernet_info* ethernet_protocol = nullptr;
vector<ethernet_info*> ethernetProtocolVec;
ip_info* ip_protocol = nullptr;
vector<ip_info*> ipProtocolVec;
udp_info* udp_protocol = nullptr;
vector<udp_info*> udpProtocolVec;
tcp_info* tcp_protocol = nullptr;
vector<tcp_info*> tcpProtocolVec;
vector<data_packet*> dataPacketVec;

// itoa 封装，转为指定进制的sting 类型
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
    memset(buf,0x00,sizeof buf);
    sprintf(buf, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return buf;
}

bool getAllAdapters() {

    if(allAdapters) freeAdapters();
    allAdapters = nullptr;
    memset(errbuf, 0x00, sizeof(errbuf));
    int ret = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf);
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

bool Sniff(int num) {
    if(num < 0) return false;
    pcap_if_t* adapters = allAdapters;
    // Why num-1
    for(int i=0; i<num-1&&adapters; i++) {
        adapters = adapters->next;
    }
    if(adapters == nullptr) return false;

    sniff = pcap_open(adapters->name, MAXDATAFRAME, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    cout << "SNIFF!!!!!!" << endl;
    if(pcap_datalink(sniff) != DLT_EN10MB) return false;
    return sniff!=nullptr;
}

bool getDataPacket() {
    packData = nullptr;
    cout << "getDataPacket!!!!!" << endl;
    int r= pcap_next_ex(sniff, &packHeader, &packData);
    return r;
}
bool captureDataPacket(pcap_pkthdr* ph, const u_char* pd) {
    cout << "getDataPacket!!!!!" << endl;
    int r= pcap_next_ex(sniff, &ph, &pd);
    cout << ph->caplen << endl;
    cout << pd << endl;
    return r;
}

bool parseFrame() {
    struct ethernet_header {
        u_char ether_dhost[6];
        u_char ether_shost[6];
        u_short ether_type;
    };
    ethernet_header* etherH = (ethernet_header*)packData;
    ethernet_protocol = new ethernet_info();

#define NTOHS(A) ((((A)&0xFF00)>>8) | (((A)&0x00FF)<<8));
    etherH->ether_type = NTOHS(etherH->ether_type);
    ethernet_protocol->mac_type = "0x" + dataToString(etherH->ether_type, 16);
    if(ethernet_protocol->mac_type != "0x800") return false;

    // dest mac address
    memset(buf, 0x00, sizeof (buf));
    sprintf(buf, " %02X:%02X:%02X:%02X:%02X:%02X ",
            etherH->ether_dhost[0],
            etherH->ether_dhost[1],
            etherH->ether_dhost[2],
            etherH->ether_dhost[3],
            etherH->ether_dhost[4],
            etherH->ether_dhost[5]);
    ethernet_protocol->mac_dest = buf;

    // source mac address
    memset(buf, 0x00, sizeof (buf));
    sprintf(buf, " %02X:%02X:%02X:%02X:%02X:%02X ",
            etherH->ether_shost[0],
            etherH->ether_shost[1],
            etherH->ether_shost[2],
            etherH->ether_shost[3],
            etherH->ether_shost[4],
            etherH->ether_shost[5]);
    ethernet_protocol->mac_src = buf;

    ethernet_protocol->mac_content += "0x";
    for(int i=0; i<6; i++) {
        string s = dataToString(etherH->ether_dhost[i], 16);
        ethernet_protocol->mac_content += string("0", 2-s.size()) + s + " ";
    }
    for(int i=0; i<6; i++) {
        string s = dataToString(etherH->ether_shost[i], 16);
        ethernet_protocol->mac_content += string("0", 2-s.size()) + s + " ";
    }
    string s = dataToString(etherH->ether_type, 16);
    ethernet_protocol->mac_content += string("0", 4-s.size()) + s;
    return true;
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
    if(dp->ethernet_header->mac_type != "0x800") return false;

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

bool parseIP() {
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
    ip_header* ipH = (ip_header*)(packData + 14);
    ip_protocol = new ip_info();

    if((ipH->ip_version_headerLen&(0x40)) == 0x40) {
        ip_protocol->ip_version = "ipv4";
    } else if((ipH->ip_version_headerLen&(0x60)) == 0x60) {
        ip_protocol->ip_version = "ipv6";
    } else {
        return false;
    }
    char len = ipH->ip_version_headerLen & 0x0f;
    if(len < 0x05) return false;
    ip_protocol->ip_headLen = "0x" + dataToString(len, 16);
    ip_protocol->ip_diffserv = "0x" + dataToString(ipH->ip_service, 16);
    ip_protocol->ip_totalLen = "0x" + dataToString(ipH->ip_totalLen, 16);
    ip_protocol->ip_identification = "0x" + dataToString(ipH->ip_identification, 16);
    char flag = ipH->ip_flag_offset >> 13;
    string fRet = dataToString(flag, 2);
    fRet = string(3-fRet.size(), '0') + fRet;
    char offset = ipH->ip_flag_offset & 0x1fff;
    string oRet = dataToString(offset, 16);
    oRet = string(4-oRet.size(), '0') + oRet;
    ip_protocol->ip_flag_offset = fRet + " 0x" + oRet;
    ip_protocol->ip_ttl = "0x" + dataToString(ipH->ip_ttl, 16);
    ip_protocol->ip_protocol = dataToString(ipH->ip_protocol, 10);
    ip_protocol->ip_checkSum = "0x" + dataToString(ipH->ip_checkSum, 16);
    ip_protocol->ip_src = iptos(ipH->ip_src);
    ip_protocol->ip_dest = iptos(ipH->ip_dest);

    //
#define FUN(S,N) string(N - S.size(),'0') + S
    ip_protocol->ip_content[0] = "0x" + FUN(dataToString(ipH->ip_version_headerLen,16),2) + " " + FUN(dataToString(ipH->ip_service,16),2) + " " + FUN(dataToString(ipH->ip_totalLen,16),4);
    ip_protocol->ip_content[1] = "0x" + FUN(dataToString(ipH->ip_identification,16),4) + " " + FUN(dataToString(ipH->ip_flag_offset,16),4);
    ip_protocol->ip_content[2] = "0x" + FUN(dataToString(ipH->ip_ttl,16),2) + " " + FUN(dataToString(ipH->ip_protocol,16),2) + " " + FUN(dataToString(ipH->ip_checkSum,16),4);
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
    dp->ip_header->ip_totalLen = "0x" + dataToString(ipH->ip_totalLen, 16);
    dp->ip_header->ip_identification = "0x" + dataToString(ipH->ip_identification, 16);
    char flag = ipH->ip_flag_offset >> 13;
    string fRet = dataToString(flag, 2);
    fRet = string(3-fRet.size(), '0') + fRet;
    char offset = ipH->ip_flag_offset & 0x1fff;
    string oRet = dataToString(offset, 16);
    oRet = string(4-oRet.size(), '0') + oRet;
    dp->ip_header->ip_flag_offset = fRet + " 0x" + oRet;
    dp->ip_header->ip_ttl = "0x" + dataToString(ipH->ip_ttl, 16);
    dp->ip_header->ip_protocol = dataToString(ipH->ip_protocol, 10);
    dp->ip_header->ip_checkSum = "0x" + dataToString(ipH->ip_checkSum, 16);
    dp->ip_header->ip_src = iptos(ipH->ip_src);
    dp->ip_header->ip_dest = iptos(ipH->ip_dest);

    //
#define FUN(S,N) string(N - S.size(),'0') + S
    dp->ip_header->ip_content[0] = "0x" + FUN(dataToString(ipH->ip_version_headerLen,16),2) + " " + FUN(dataToString(ipH->ip_service,16),2) + " " + FUN(dataToString(ipH->ip_totalLen,16),4);
    dp->ip_header->ip_content[1] = "0x" + FUN(dataToString(ipH->ip_identification,16),4) + " " + FUN(dataToString(ipH->ip_flag_offset,16),4);
    dp->ip_header->ip_content[2] = "0x" + FUN(dataToString(ipH->ip_ttl,16),2) + " " + FUN(dataToString(ipH->ip_protocol,16),2) + " " + FUN(dataToString(ipH->ip_checkSum,16),4);
    return true;
}

bool parseTransport(int num) {
    bool ret = false;
    switch(atoi(ip_protocol->ip_protocol.c_str())) {
    case 1:
        if(num!=0 && num!=2) return false;
        ret = parseICMP();
        break;
    case 6:
        if(num!=0 && num!=3) return false;
        ret = parseTCP();
        break;
    case 17:
        if(num!=0 && num!=2) return false;
        ret = parseUDP();
        break;
    }

    return ret;
}
bool parseTransportProtocol(data_packet* dp, const u_char* d) {

}


bool parseTCP() {
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
    tcp_header* tcpH = (tcp_header*)(packData + 14 + 20);
    tcp_protocol = new tcp_info();

    tcp_protocol->tcp_sport = "0x" + dataToString(tcpH->tcp_sport, 16) + "(" + to_string(tcpH->tcp_sport) + ")";
    tcp_protocol->tcp_dport = "0x" + dataToString(tcpH->tcp_dport, 16) + "(" + to_string(tcpH->tcp_dport) + ")";
    tcp_protocol->tcp_seqNum = "0x" + dataToString(tcpH->tcp_seqNum, 16) + "(" + to_string(tcpH->tcp_seqNum) + ")";
    tcp_protocol->tcp_ackNum = "0x" + dataToString(tcpH->tcp_ackNum, 16) + "(" + to_string(tcpH->tcp_ackNum) + ")";


#define FUN(S, N) string(N - S.size(),'0') + S
    string offset = dataToString(tcpH->tcp_off_res_flag & 0xf000 >> 12, 2);
    tcp_protocol->tcp_offset_res_flag = FUN(offset, 4);
    string reserve = dataToString(tcpH->tcp_off_res_flag & 0x0fc0 >> 6, 2);
    tcp_protocol->tcp_offset_res_flag += FUN(reserve, 4);
    string flag = dataToString(tcpH->tcp_off_res_flag & 0x003f, 2);
    tcp_protocol->tcp_offset_res_flag = FUN(flag, 4);
    tcp_protocol->tcp_windowSize = "0x" + dataToString(tcpH->tcp_winSize, 16);
    tcp_protocol->tcp_checkSum = "0x" + dataToString(tcpH->tcp_checkSum, 16);
    tcp_protocol->tcp_urgentPoint = "0x" + dataToString(tcpH->tcp_urgentPoint, 16);
    tcp_protocol->tcp_content[0] = "0x" + FUN(dataToString(tcpH->tcp_sport, 16), 4) + " " + FUN(dataToString(tcpH->tcp_dport, 16), 4);
    tcp_protocol->tcp_content[1] = "0x" + FUN(dataToString(tcpH->tcp_seqNum, 16), 8);
    tcp_protocol->tcp_content[2] = "0x" + FUN(dataToString(tcpH->tcp_ackNum, 16), 8);
    tcp_protocol->tcp_content[3] = "0x" + FUN(dataToString(tcpH->tcp_off_res_flag, 16), 4) + " " + FUN(dataToString(tcpH->tcp_winSize, 16), 4);
    tcp_protocol->tcp_content[4] = "0x" + FUN(dataToString(tcpH->tcp_checkSum, 16), 4) + " " + FUN(dataToString(tcpH->tcp_urgentPoint, 16), 4);

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

    dp->tcp_header->tcp_sport = "0x" + dataToString(tcpH->tcp_sport, 16) + "(" + to_string(tcpH->tcp_sport) + ")";
    dp->tcp_header->tcp_dport = "0x" + dataToString(tcpH->tcp_dport, 16) + "(" + to_string(tcpH->tcp_dport) + ")";
    dp->tcp_header->tcp_seqNum = "0x" + dataToString(tcpH->tcp_seqNum, 16) + "(" + to_string(tcpH->tcp_seqNum) + ")";
    dp->tcp_header->tcp_ackNum = "0x" + dataToString(tcpH->tcp_ackNum, 16) + "(" + to_string(tcpH->tcp_ackNum) + ")";
    cout << "port over!" << endl;

#define FUN(S, N) string(N - S.size(),'0') + S
    string offset = dataToString(tcpH->tcp_off_res_flag & 0xf000 >> 12, 2);
    dp->tcp_header->tcp_offset_res_flag = FUN(offset, 4);
    cout << "offset over!" << endl;

    //string reserve = dataToString(tcpH->tcp_off_res_flag & 0x0fc0 >> 6, 2);
    //dp->tcp_header->tcp_offset_res_flag += FUN(reserve, 4);
    //cout << "reserve over!" << endl;

    /*string flag = dataToString(tcpH->tcp_off_res_flag & 0x003f, 2);
    dp->tcp_header->tcp_offset_res_flag = FUN(flag, 4);
    dp->tcp_header->tcp_windowSize = "0x" + dataToString(tcpH->tcp_winSize, 16);
    dp->tcp_header->tcp_checkSum = "0x" + dataToString(tcpH->tcp_checkSum, 16);
    dp->tcp_header->tcp_urgentPoint = "0x" + dataToString(tcpH->tcp_urgentPoint, 16);
    dp->tcp_header->tcp_content[0] = "0x" + FUN(dataToString(tcpH->tcp_sport, 16), 4) + " " + FUN(dataToString(tcpH->tcp_dport, 16), 4);
    dp->tcp_header->tcp_content[1] = "0x" + FUN(dataToString(tcpH->tcp_seqNum, 16), 8);
    dp->tcp_header->tcp_content[2] = "0x" + FUN(dataToString(tcpH->tcp_ackNum, 16), 8);
    dp->tcp_header->tcp_content[3] = "0x" + FUN(dataToString(tcpH->tcp_off_res_flag, 16), 4) + " " + FUN(dataToString(tcpH->tcp_winSize, 16), 4);
    dp->tcp_header->tcp_content[4] = "0x" + FUN(dataToString(tcpH->tcp_checkSum, 16), 4) + " " + FUN(dataToString(tcpH->tcp_urgentPoint, 16), 4);
    cout << "content over!" << endl;*/
    return true;
}

bool parseUDP() {
    struct udp_header {
        u_short udp_sport;
        u_short udp_dport;
        u_short udp_length;
        u_short udp_checkSum;
    };
    udp_header* udpH = (udp_header*)(packData + 14 + 20);
    udp_protocol = new udp_info();
    udp_protocol->udp_sport = "0x" + dataToString(udpH->udp_sport,16) + "(" + to_string(udpH->udp_sport) + ")";
    udp_protocol->udp_dport = "0x" +dataToString(udpH->udp_dport,16) + "(" + to_string(udpH->udp_dport) + ")";
    udp_protocol->udp_len = "0x" +dataToString(udpH->udp_length,16);
    udp_protocol->udp_checkSum = "0x" +dataToString(udpH->udp_checkSum,16);
#define FUN(S, N) string(N - S.size(), '0') + S
    udp_protocol->udp_content[0] = "0x" + FUN(dataToString(udpH->udp_sport, 16), 4) + " " + FUN(dataToString(udpH->udp_dport, 16), 4);
    udp_protocol->udp_content[1] = "0x" + FUN(dataToString(udpH->udp_length, 16), 4) + " " + FUN(dataToString(udpH->udp_checkSum, 16), 4);
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
#define FUN(S, N) string(N - S.size(), '0') + S
    dp->udp_header->udp_content[0] = "0x" + FUN(dataToString(udpH->udp_sport, 16), 4) + " " + FUN(dataToString(udpH->udp_dport, 16), 4);
    dp->udp_header->udp_content[1] = "0x" + FUN(dataToString(udpH->udp_length, 16), 4) + " " + FUN(dataToString(udpH->udp_checkSum, 16), 4);
    return true;
}

bool parseICMP() {
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

    return true;
}


bool freeAdapters() {
    pcap_freealldevs(allAdapters);
    return true;
}
