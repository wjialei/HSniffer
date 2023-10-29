#ifndef PACKETTABLEITEM_H
#define PACKETTABLEITEM_H

#include <string>
using namespace std;
class PacketTableItem {

public:
    PacketTableItem();
    PacketTableItem(string tm, string ms, string md, unsigned int dl, string pt, string is, string id);
    string time;
    string mac_src;
    string mac_dest;
    unsigned int data_len;
    string protocol_type;
    string ip_src;
    string ip_dest;    
};
#endif // PACKETTABLEITEM_H
