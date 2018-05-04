#ifndef ARPPACKET_H
#define ARPPACKET_H
#include "public_header.h"
#include "public_qt_header.h"
#include "winsock2.h"
#include "packet.h"
#define PADDING 18
#define ETHERLEN 14
#define ARPLEN 28
class ArpPacket
{
public:
    ArpPacket(const u_char * sourceMAC,const u_char *sourceIP
              ,const u_char *targetIP);
    u_char d[ETHERLEN+ARPLEN+PADDING]={0};
};

#endif // ARPPACKET_H
