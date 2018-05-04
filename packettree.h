#ifndef PACKETTREE_H
#define PACKETTREE_H
#include "public_header.h"
#include "public_qt_header.h"
#include "packet.h"
#include <QTreeWidgetItem>

class PacketTree:public QTreeWidget
{
    Q_OBJECT
public:
    PacketTree();
    QList<QTreeWidgetItem*> list;
public slots:
    void setPacket(Packet* p);
private:
    void showEthernetLayer();
    void showNetworkLayer();
    void showTransportLayer();
    void showApplicationLayer();
private:
    Packet *p;
};

#endif // PACKETTREE_H
