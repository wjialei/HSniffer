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

    //qRegisterMetaType<string>("string");
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
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::recMsgfromCap(PacketTableItem pti) {
    //cout << "str: " << str << endl;
    //cout << "mac: " << ethernet_protocol->mac_content << endl;

    int rcnt = ui->packetTable->rowCount();
    ui->packetTable->insertRow(rcnt);
    //ui->packetTable->setItem(rcnt, 0, new QTableWidgetItem(QString::number(rcnt)));
    /*ui->packetTable->setItem(rcnt, 1, new QTableWidgetItem(QString::fromStdString(ethernet_protocol->mac_src)));
    ui->packetTable->setItem(rcnt, 2, new QTableWidgetItem(QString::fromStdString(ethernet_protocol->mac_dest)));
    ui->packetTable->setItem(rcnt, 4, new QTableWidgetItem(QString::fromStdString(ip_protocol->ip_protocol)));
    ui->packetTable->setItem(rcnt, 5, new QTableWidgetItem(QString::fromStdString(ip_protocol->ip_src)));
    ui->packetTable->setItem(rcnt, 6, new QTableWidgetItem(QString::fromStdString(ip_protocol->ip_dest)));*/
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
    emit sendAdapterIndex(adapterIndex);
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
    ui->packetDataText->insertPlainText(QString::fromStdString(ethernetProtocolVec[row]->mac_content));
    ui->packetDataText->setReadOnly(true);
}

void MainWindow::on_packetTable_cellDoubleClicked(int row, int column)
{
    string ans = "unknown";
    switch(atoi(ipProtocolVec[row]->ip_protocol.c_str())) {
    case 1:
        ans = "ICMP";
        break;
    case 6:
        ans = "TCP";
        break;
    case 17:
        ans = "UDP";
        break;
    }
    cout << "PROTOCOL TYPE:" << ans << endl;
}
