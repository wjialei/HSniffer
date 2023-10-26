#include "mainwindow.h"

#include <QApplication>

#include <iostream>
using namespace std;

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}

//#include <WinSock2.h>
//#include <Windows.h>
//#include <pcap.h>
//#include <iostream>

//#pragma comment(lib, "packet.lib")
//#pragma comment(lib, "wpcap.lib")

//// 输出 数据链路层
//void PrintEtherHeader(const u_char * packetData)
//{
//    typedef struct ether_header {
//        u_char ether_dhost[6];    // 目标地址
//        u_char ether_shost[6];    // 源地址
//        u_short ether_type;       // 以太网类型
//    } ether_header;

//    ether_header * eth_protocol;
//    eth_protocol = (ether_header *)packetData;

//    //u_short ether_type = ntohs(eth_protocol->ether_type);  // 以太网类型
//    u_char *ether_src = eth_protocol->ether_shost;         // 以太网原始MAC地址
//    u_char *ether_dst = eth_protocol->ether_dhost;         // 以太网目标MAC地址

//    //printf("类型: 0x%x \t", ether_type);
//    printf("SRC MAC: %02X:%02X:%02X:%02X:%02X:%02X \t",
//         ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
//    printf("DEST MAC: %02X:%02X:%02X:%02X:%02X:%02X \n",
//         ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
//}




//void MonitorAdapter(int nChoose)
//{
//    pcap_if_t *adapters;
//    char errbuf[PCAP_ERRBUF_SIZE];

//    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &adapters, errbuf) != -1)
//    {
//        // 找到指定的网卡
//        for (int x = 0; x < nChoose - 1; ++x)
//            adapters = adapters->next;

//        char errorBuf[PCAP_ERRBUF_SIZE];

//        // PCAP_OPENFLAG_PROMISCUOUS = 网卡设置为混杂模式
//        // 1000 => 1000毫秒如果读不到数据直接返回超时
//        pcap_t * handle = pcap_open(adapters->name, 65534, 1, PCAP_OPENFLAG_PROMISCUOUS, 0, 0);

//        if (adapters == NULL)
//            return;

//        // printf("开始侦听: % \n", adapters->description);
//        pcap_pkthdr *Packet_Header;    // 数据包头
//        const u_char * Packet_Data;    // 数据本身
//        int retValue;
//        while ((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) >= 0)
//        {
//            if (retValue == 0)
//                continue;
//            // printf("侦听长度: %d \n", Packet_Header->len);
//            PrintEtherHeader(Packet_Data);
//        }
//    }
//}



//int main(int argc,char *argv[])
//{
//    MonitorAdapter(8);
//}
