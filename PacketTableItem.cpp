#include <PacketTableItem.h>

PacketTableItem::PacketTableItem() {

}

PacketTableItem::PacketTableItem(string ms, string md, unsigned int dl, string pt, string is, string id) {
    mac_src = ms;
    mac_dest = md;
    data_len = dl;
    protocol_type = pt;
    ip_src = is;
    ip_dest = id;
}
