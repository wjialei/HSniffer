#include "mainwindow.h"

#include <QApplication>
#include <WinSock2.h>
#include <Windows.h>
#include <pcap.h>

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")

int enumAdapters()
{
    pcap_if_t *allAdapters;    // 所有网卡设备保存
    pcap_if_t *ptr;            // 用于遍历的指针
    int index = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获取本地机器设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
    {
        /* 打印网卡信息列表 */
        for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
        {
             // printf("网卡地址: %x 网卡ID: %s \n", ptr->addresses, ptr->name);
            ++index;
            if (ptr->description)
                printf("ID: %d --> Name: %s \n", index,ptr->description);
        }
    }

    /* 不再需要设备列表了，释放它 */
    pcap_freealldevs(allAdapters);
    return index;
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    int network = enumAdapters();
    printf("Count: %d \n", network);
    system("Pause");
    return a.exec();
}
