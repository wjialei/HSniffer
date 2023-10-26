#include <control.h>

bool getAdapterInfo() {
    return getAllAdapters();
}

bool parse() {
    int cnt = 0;
    bool ret = false;

    while(cnt++ < 1) {
        ret = getDataPacket();
        if(!ret) continue;

        ret = parseFrame();
        if(!ret) continue;

        ret = parseIP();
        if(!ret) continue;

        ret = parseTransport(1);
        if(!ret) continue;

        return true;
    }
    return false;

}

string getTransProtocol() {
    string ans = "unknown";
    switch(atoi(ip_protocol->ip_protocol.c_str())) {
    case 1:
        ans = "ICMP";
        break;
    case 2:
        ans = "TCP";
        break;
    case 3:
        ans = "UDP";
        break;
    }
    return ans;
}

bool closeAdapter() {
    return freeAdapters();
}
