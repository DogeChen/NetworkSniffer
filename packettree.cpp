#include "packettree.h"

PacketTree::PacketTree():QTreeWidget()
{

}

void PacketTree::setPacket(Packet *p)
{
    qDebug()<<"set packet";
    this->clear();

    setHeaderLabel(QString("Protocol"));
    list.clear();
    this->p=p;
    qDebug()<<"clear";
    if(p->ethernetHeader!=NULL){
        showEthernetLayer();
    }
    qDebug()<<"ether";
    if(p->networkHeader!=NULL){
        showNetworkLayer();
    }
    qDebug()<<"network";
    if(p->transportHeader!=NULL){
        showTransportLayer();
    }
    if(p->applicationHeader!=NULL){
        showApplicationLayer();
    }
    qDebug()<<"transport";
    addTopLevelItems(list);
    qDebug()<<"add tree finish";
    //todo expend
//    if(packet-)
}

void PacketTree::showEthernetLayer()
{
    list.append(p->ethernetHeader->getQTreeWidgetItem());
}

void PacketTree::showNetworkLayer()
{
    list.append(p->networkHeader->getTreeWidgetItems());
}

void PacketTree::showTransportLayer()
{
    list.append(p->transportHeader->getTreeWidgetItems());
}

void PacketTree::showApplicationLayer()
{
    list.append(p->applicationHeader->getTreeWidgetItem());
}
