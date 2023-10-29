#include <CapThread.h>
#include <iostream>
using namespace std;

bool capFlag = true;
pcap_pkthdr* ph;

void CapThread::run()
{
    while (capFlag) {
        // 抓取数据包

        Sniff(adapterIndex, rule);

        bool ret = getDataPacket();
        if(!ret) continue;
        data_packet* dp = new data_packet();
        parseEthernetProtocol(dp, packData);
        string protocol_str;
        if(dp->ethernet_header->mac_type == "0x800") {
            parseNetworkProtocol(dp, packData);
            switch(atoi(dp->ip_header->ip_protocol.c_str())) {
            case 1:
                parseIcmpProtocol(dp, packData);
                protocol_str = "ICMP";
                break;
            case 6:
                parseTcpProtocol(dp, packData);
                protocol_str = "TCP";
                break;
            case 17:
                parseUdpProtocol(dp, packData);
                protocol_str = "UDP";
                break;
            default:
                continue;
            }
            packHeaderVec.push_back(packHeader);
            rawDataVec.push_back(packData);
            dataPacketVec.push_back(dp);
            // 获取数据包的时间戳
            struct timeval timestamp = packHeader->ts;

            // 获取秒数
            time_t seconds = timestamp.tv_sec;

            // 将秒数转换为tm结构
            struct tm* timeinfo = localtime(&seconds);

            // 格式化为日期和时间格式
            char time_str[30];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
            PacketTableItem pti = {time_str, dp->ethernet_header->mac_src, dp->ethernet_header->mac_dest, packHeader->caplen, protocol_str, dp->ip_header->ip_src, dp->ip_header->ip_dest};
            emit sendMsgtoMain(pti);
        } else if(dp->ethernet_header->mac_type == "0x806") {
            parseArpProtocol(dp, packData);
            packHeaderVec.push_back(packHeader);
            rawDataVec.push_back(packData);
            dataPacketVec.push_back(dp);
            protocol_str = "ARP";
            // 获取数据包的时间戳
            struct timeval timestamp = packHeader->ts;

            // 获取秒数
            time_t seconds = timestamp.tv_sec;

            // 将秒数转换为tm结构
            struct tm* timeinfo = localtime(&seconds);

            // 格式化为日期和时间格式
            char time_str[30];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
            PacketTableItem pti = {time_str, dp->ethernet_header->mac_src, dp->ethernet_header->mac_dest, packHeader->caplen, protocol_str, dp->arp_header->arp_sip, dp->arp_header->arp_dip};
            emit sendMsgtoMain(pti);

        } else if(dp->ethernet_header->mac_type == "0x86dd"){
            packHeaderVec.push_back(packHeader);
            rawDataVec.push_back(packData);
            dataPacketVec.push_back(dp);
            protocol_str = "IPv6";
            // 获取数据包的时间戳
            struct timeval timestamp = packHeader->ts;

            // 获取秒数
            time_t seconds = timestamp.tv_sec;

            // 将秒数转换为tm结构
            struct tm* timeinfo = localtime(&seconds);

            // 格式化为日期和时间格式
            char time_str[30];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
            PacketTableItem pti = {time_str, dp->ethernet_header->mac_src, dp->ethernet_header->mac_dest, packHeader->caplen, protocol_str, "ipv6_src", "ipv6_dest"};
            emit sendMsgtoMain(pti);
        }
    }
}

void CapThread::recAdapterIndex(int i, string r) {
    adapterIndex = i;
    rule = r;
}
