#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <HPcap.h>
#include <QMessageBox>
#include <QTableWidgetItem>

#include <iostream>
using namespace std;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    ct = new CapThread;
    ui->setupUi(this);
    // 绑定主线程的网卡编号信号和抓包线程的网卡编号接收槽
    connect(this, &MainWindow::sendAdapterIndex, ct, &CapThread::recAdapterIndex);

    qRegisterMetaType<PacketTableItem>("PacketTableItem");

    connect(ct, &CapThread::sendMsgtoMain, this, &MainWindow::recMsgfromCap);

    ui->finishCapButton->setEnabled(false);

    ui->adaptersComboBox->addItem(tr("请选择一个网卡接口"));
    int ret = getAllAdapters();
    if(ret == false) {
       QMessageBox::warning(this, tr("Sniffer"), tr("无法获取网卡接口"), QMessageBox::Ok);
    } else {
        for(pcap_if_t* ptr = allAdapters; ptr!=NULL; ptr=ptr->next) {
            ui->adaptersComboBox->addItem(QString("%1").arg(ptr->description));
        }
    }

    ui->packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetDataText->setReadOnly(true);
    ui->packetParseText->setReadOnly(true);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::recMsgfromCap(PacketTableItem pti) {

    int rcnt = ui->packetTable->rowCount();
    ui->packetTable->insertRow(rcnt);
    ui->packetTable->setItem(rcnt, 0, new QTableWidgetItem(QString::fromStdString(pti.time)));
    ui->packetTable->setItem(rcnt, 1, new QTableWidgetItem(QString::fromStdString(pti.mac_src)));
    ui->packetTable->setItem(rcnt, 2, new QTableWidgetItem(QString::fromStdString(pti.mac_dest)));
    ui->packetTable->setItem(rcnt, 3, new QTableWidgetItem(QString::number(pti.data_len)));
    ui->packetTable->setItem(rcnt, 4, new QTableWidgetItem(QString::fromStdString(pti.protocol_type)));
    ui->packetTable->setItem(rcnt, 5, new QTableWidgetItem(QString::fromStdString(pti.ip_src)));
    ui->packetTable->setItem(rcnt, 6, new QTableWidgetItem(QString::fromStdString(pti.ip_dest)));
}

void MainWindow::on_startCapButton_clicked()
{
    int adapterIndex = ui->adaptersComboBox->currentIndex();
    string rule = ui->ruleLineEdit->text().toStdString();
    emit sendAdapterIndex(adapterIndex, rule);
    capFlag = true;

    ct->start();
    ui->finishCapButton->setEnabled(true);
    ui->startCapButton->setEnabled(false);

}

void MainWindow::on_finishCapButton_clicked()
{
    capFlag = false;
    ui->finishCapButton->setEnabled(false);
    ui->startCapButton->setEnabled(true);
}

void MainWindow::on_packetTable_cellClicked(int row, int column)
{
    ui->packetDataText->clear();
    QString hexString; // 用于存储十六进制字符串

    for (int i = 0; i < packHeaderVec[row]->len; i++) {
        // 将输出内容构建成一个 QString
        hexString += QString("%1 ").arg(static_cast<int>(rawDataVec[row][i]), 2, 16, QChar('0'));

        if ((i + 1) % 16 == 0) {
            // 在每行的末尾追加一个空格，并将整个行追加到 QPlainTextEdit 中
            hexString += " ";
            for (int j = i - 15; j <= i; j++) {
                if (j >= 0 && j < packHeaderVec[row]->len) {
                    char byte = rawDataVec[row][j];
                    if (byte >= 32 && byte <= 126) {
                        hexString += byte;
                    } else {
                        hexString += '.'; // 如果不是可打印字符，用点号代替
                    }
                } else {
                    hexString += ' '; // 如果没有数据，追加空格
                }
            }
            ui->packetDataText->appendPlainText(hexString);
            hexString.clear(); // 清空 hexString
        }
    }

    // 将剩余的内容追加到 QPlainTextEdit
    if (!hexString.isEmpty()) {
        ui->packetDataText->appendPlainText(hexString);
    }

}

void MainWindow::on_packetTable_cellDoubleClicked(int row, int column)
{
    ui->packetParseText->clear();
    string s = getProtocol(dataPacketVec[row]);
    if(s == "TCP") {
        showTCP(row);
    } else if(s == "UDP") {
        showUDP(row);
    } else if(s == "ARP") {
        showARP(row);
    } else if(s == "ICMP") {
        showICMP(row);
    }
}

void MainWindow::showTCP(int i) {
    QString info;
    QString ether_output = QString("EthernetInfo: {mac_dest: %1, mac_src: %2, mac_type: %3, mac_content: %4}\n")
            .arg(dataPacketVec[i]->ethernet_header->mac_dest.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_src.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_type.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_content.c_str());

    QString ip_output = QString("IPInfo: {ip_version: %1, ip_headLen: %2, ip_diffserv: %3, ip_totalLen: %4, "
                                "ip_identification: %5, ip_flag_offset: %6, ip_ttl: %7, ip_protocol: %8, "
                                "ip_checkSum: %9, ip_src: %10, ip_dest: %11, "
                                "ip_content: {%12, %13, %14, %15}}\n")
           .arg(dataPacketVec[i]->ip_header->ip_version.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_headLen.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_diffserv.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_totalLen.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_identification.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_flag_offset.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_ttl.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_protocol.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_checkSum.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_src.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_dest.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[0].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[1].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[2].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[3].c_str());

    QString tcp_output = QString("TCPInfo: {tcp_sport: %1, tcp_dport: %2, tcp_seqNum: %3, tcp_ackNum: %4, "
                                 "tcp_offset_res_flag: %5, tcp_windowSize: %6, tcp_checkSum: %7 "
                                 "tcp_urgentPoint: %8, tcp_content: {%9, %10, %11, %12, %13}}")
            .arg(dataPacketVec[i]->tcp_header->tcp_sport.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_dport.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_seqNum.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_ackNum.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_offset_res_flag.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_windowSize.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_checkSum.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_urgentPoint.c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_content[0].c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_content[1].c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_content[2].c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_content[3].c_str())
            .arg(dataPacketVec[i]->tcp_header->tcp_content[4].c_str());
    info = ether_output + ip_output + tcp_output;
    ui->packetParseText->appendPlainText(info);

}

void MainWindow::showUDP(int i) {
    QString info;
    QString ether_output = QString("EthernetInfo: {mac_dest: %1, mac_src: %2, mac_type: %3, mac_content: %4}\n")
            .arg(dataPacketVec[i]->ethernet_header->mac_dest.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_src.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_type.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_content.c_str());

    QString ip_output = QString("IPInfo: {ip_version: %1, ip_headLen: %2, ip_diffserv: %3, ip_totalLen: %4, "
                                "ip_identification: %5, ip_flag_offset: %6, ip_ttl: %7, ip_protocol: %8, "
                                "ip_checkSum: %9, ip_src: %10, ip_dest: %11, "
                                "ip_content: {%12, %13, %14, %15}}\n")
           .arg(dataPacketVec[i]->ip_header->ip_version.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_headLen.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_diffserv.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_totalLen.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_identification.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_flag_offset.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_ttl.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_protocol.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_checkSum.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_src.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_dest.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[0].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[1].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[2].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[3].c_str());

    QString udp_output = QString("UDPInfo: {udp_sport: %1, udp_dport: %2, udp_len: %3, udp_checkSum: %4, "
                                 "udp_content: {%5, %6}}\n")
            .arg(dataPacketVec[i]->udp_header->udp_sport.c_str())
            .arg(dataPacketVec[i]->udp_header->udp_dport.c_str())
            .arg(dataPacketVec[i]->udp_header->udp_len.c_str())
            .arg(dataPacketVec[i]->udp_header->udp_checkSum.c_str())
            .arg(dataPacketVec[i]->udp_header->udp_content[0].c_str())
            .arg(dataPacketVec[i]->udp_header->udp_content[1].c_str());

    info = ether_output + ip_output + udp_output;
    ui->packetParseText->appendPlainText(info);
}

void MainWindow::showARP(int i) {
    QString info;
    QString ether_output = QString("EthernetInfo: {mac_dest: %1, mac_src: %2, mac_type: %3, mac_content: %4}\n")
            .arg(dataPacketVec[i]->ethernet_header->mac_dest.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_src.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_type.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_content.c_str());

    QString arp_output = QString("ARPInfo: {arp_htype: %1, arp_ptype: %2, arp_hsize: %3, arp_psize: %4, "
                                 "arp_opcpde: %5, arp_src: %6， arp_sip: %7, arp_dest: %8, arp_dip: %9}\n")
           .arg(dataPacketVec[i]->arp_header->arp_htype.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_ptype.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_hsize.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_psize.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_opcode.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_src.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_sip.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_dest.c_str())
           .arg(dataPacketVec[i]->arp_header->arp_dip.c_str());


    info = ether_output + arp_output;
    ui->packetParseText->appendPlainText(info);
}

void MainWindow::showICMP(int i) {
    QString info;
    QString ether_output = QString("EthernetInfo: {mac_dest: %1, mac_src: %2, mac_type: %3, mac_content: %4}\n")
            .arg(dataPacketVec[i]->ethernet_header->mac_dest.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_src.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_type.c_str())
            .arg(dataPacketVec[i]->ethernet_header->mac_content.c_str());

    QString ip_output = QString("IPInfo: {ip_version: %1, ip_headLen: %2, ip_diffserv: %3, ip_totalLen: %4, "
                                "ip_identification: %5, ip_flag_offset: %6, ip_ttl: %7, ip_protocol: %8, "
                                "ip_checkSum: %9, ip_src: %10, ip_dest: %11, "
                                "ip_content: {%12, %13, %14, %15}}\n")
           .arg(dataPacketVec[i]->ip_header->ip_version.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_headLen.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_diffserv.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_totalLen.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_identification.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_flag_offset.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_ttl.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_protocol.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_checkSum.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_src.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_dest.c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[0].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[1].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[2].c_str())
           .arg(dataPacketVec[i]->ip_header->ip_content[3].c_str());

    QString icmp_output = QString("ICMPInfo: {icmp_type: %1, icmp_code: %2, icmp_checkSum: %3, icmp_identification: %4, "
                                 "icmp_seq: %5, icmp_initTime: %6, icmp_recvTime: %7, icmp_sendTime: %8}\n")
            .arg(dataPacketVec[i]->icmp_header->icmp_type.c_str())
            .arg(dataPacketVec[i]->icmp_header->icmp_code.c_str())
            .arg(dataPacketVec[i]->icmp_header->icmp_checkSum.c_str())
            .arg(dataPacketVec[i]->icmp_header->icmp_identification.c_str())
            .arg(dataPacketVec[i]->icmp_header->icmp_seq.c_str())
            .arg(dataPacketVec[i]->icmp_header->icmp_initTime.c_str())
            .arg(dataPacketVec[i]->icmp_header->icmp_recvTime.c_str())
            .arg(dataPacketVec[i]->icmp_header->icmp_sendTime.c_str());

    info = ether_output + ip_output + icmp_output;
    ui->packetParseText->appendPlainText(info);
}
