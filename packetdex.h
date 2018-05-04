#ifndef PACKETDEX_H
#define PACKETDEX_H

#include "public_header.h"
#include "public_qt_header.h"
#include "packet.h"
#include "QTableWidgetItem"
class PacketDex:public QTableWidget
{
    Q_OBJECT
public:
    PacketDex();
public slots:
    void setPacket(Packet* p);
};

#endif // PACKETDEX_H
