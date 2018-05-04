#ifndef PACKETTABLE_H
#define PACKETTABLE_H
#include "public_header.h"
#include "public_qt_header.h"
#include "packet.h"
#include <QVector>
#include <QWidget>
class PacketTable:public QTableWidget
{
    Q_OBJECT
public:
    QVector<Packet*> packets;
private:    static const int columns=9;

public:
    PacketTable();
public slots:
    void newPacketIn(Packet* p);
    void clearPackets();
    void onPacketClicked(QTableWidgetItem* item);
signals:
    void onPacketClickedSignal(Packet* p);
};

#endif // PACKETTABLE_H
