#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QThread>
#include <HPcap.h>
#include <PacketTableItem.h>
extern bool capFlag;
extern const u_char* pd;
extern pcap_pkthdr* ph;
class CapThread : public QThread {
    Q_OBJECT

public:
    void run();

public slots:
    void recAdapterIndex(int);

private:
    int adapterIndex;

signals:
    void sendMsgtoMain(PacketTableItem);

};



#endif // CAPTHREAD_H
