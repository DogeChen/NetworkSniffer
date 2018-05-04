#include "packettable.h"

PacketTable::PacketTable():QTableWidget(0,8)
{

    QStringList header=QStringList();

    header<<"序号"<<"时间"<<"长度"
         <<"src mac"<<"des mac"<<"protocol"
        <<"src ip"<<"des ip";
    setHorizontalHeaderLabels(header);
    //click
    connect(this,SIGNAL(itemClicked(QTableWidgetItem*))
           ,this,SLOT(onPacketClicked(QTableWidgetItem*)));

    this->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    this->verticalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    this->horizontalHeader()->setSortIndicatorShown(true);
    this->verticalHeader()->hide();
    connect(this->horizontalHeader(),SIGNAL(sectionClicked(int))
            ,this,SLOT(sortByColumn(int)));

}

void PacketTable::newPacketIn(Packet *p)
{
    if(this->rowCount()>5000){
        qDebug()<<"table is full";
        return;
    }
    packets.push_back(p);
    int row=this->rowCount();
    this->setRowCount(row+1);
    bool ok;

    QVariant num=row;
    int column=0;
    QTableWidgetItem * tp=new QTableWidgetItem();
    tp->setData(Qt::EditRole,num);
    tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);

    this->setItem(row,column++,tp);

    tp=new QTableWidgetItem(p->time);
    tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
    this->setItem(row,column++,tp);

//    tp=new QTableWidgetItem();
//    tp->setData(Qt::EditRole,p->caplen);
//    tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
//    this->setItem(row,column++,tp);


    tp=new QTableWidgetItem();
    tp->setData(Qt::EditRole,p->len);
    tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
    this->setItem(row,column++,tp);

    tp=new QTableWidgetItem(p->ethernetHeader->getSrcMac());
    tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
    this->setItem(row,column++,tp);

    tp=new QTableWidgetItem(p->ethernetHeader->getDesMac());
    tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
    this->setItem(row,column++,tp);

    tp=new QTableWidgetItem(p->protocol);
    tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
    this->setItem(row,column++,tp);

    if(p->ethernetHeader->type==IP_PROTOCOL||p->ethernetHeader->type==ARP_PROTOCOL)
    {
        QString srcIP=p->networkHeader->getSrcIP();
        QString desIP=p->networkHeader->getDesIP();
        tp=new QTableWidgetItem(srcIP);
        tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,column++,tp);
        tp=new QTableWidgetItem(desIP);
        tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,column++,tp);
    }
}

void PacketTable::clearPackets()
{
    packets.clear();
//    this->clear();
    this->setRowCount(0);
}

void PacketTable::onPacketClicked(QTableWidgetItem *item)
{

    int num=this->item(item->row(),0)->text().toInt();
    qDebug()<<"click row ="<<num;
    if(num>=0){
        Packet* p= packets.at(num);
        p->print_packet();
        emit onPacketClickedSignal(p);
    }
}
