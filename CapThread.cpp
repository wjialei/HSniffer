#include <CapThread.h>
#include <iostream>
using namespace std;

bool capFlag = true;
const u_char* pd;
pcap_pkthdr* ph;
void CapThread::run()
{
    while (capFlag) {
        // 抓取数据包
        getAllAdapters();
        Sniff(adapterIndex);

        //bool ret = captureDataPacket(ph, pd);
        //cout << ph->caplen << endl;
        bool ret = getDataPacket();
        if(!ret) continue;
        //packDataVec.push_back(packData);
        data_packet* dp = new data_packet();
        parseEthernetProtocol(dp, packData);
        cout << "mac over" << endl;
        if(dp->ethernet_header->mac_type == "0x800") {
            parseNetworkProtocol(dp, packData);
            cout << "ip over" << endl;
            switch(atoi(dp->ip_header->ip_protocol.c_str())) {
//            case 1:
//                cout << "icmp" << endl;
//                parseIcmpProtocol(dp, packData);
//                cout << "icmp over" << endl;
//                break;
            case 6:
                cout << "tcp" << endl;
                parseTcpProtocol(dp, packData);
                cout << "tcp over" << endl;
                break;
//            case 17:
//                cout << "udp" << endl;
//                parseUdpProtocol(dp, packData);
//                cout << "udp over" << endl;
//                break;
            }
        } else if(dp->ethernet_header->mac_type == "0x806") {
            cout << "arp" << endl;
        }
        cout << "********" << endl;
        PacketTableItem pti = {dp->ethernet_header->mac_src, dp->ethernet_header->mac_dest, packHeader->caplen, dp->ethernet_header->mac_type, dp->ip_header->ip_src, dp->ip_header->ip_dest};
        emit sendMsgtoMain(pti);
    }
}

void CapThread::recAdapterIndex(int i) {
    adapterIndex = i;
}
