#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QThread>
#include <HPcap.h>
#include <PacketTableItem.h>
#include <ctime>
extern bool capFlag;
extern pcap_pkthdr* ph;

class CapThread : public QThread {
    Q_OBJECT

public:
    void run();

public slots:
    void recAdapterIndex(int, string);

private:
    int adapterIndex;
    string rule;

signals:
    void sendMsgtoMain(PacketTableItem);

};



#endif // CAPTHREAD_H
