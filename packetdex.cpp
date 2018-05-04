#include "packetdex.h"

PacketDex::PacketDex():QTableWidget()
{

}

void PacketDex::setPacket(Packet *p)
{
    this->clear();
    int len=p->len;
    qDebug()<<"len = "<<len;
    qDebug()<<"caplen = "<<p->caplen;
    this->setColumnCount(16*2+1);

    int line=len/16+(len%16?1:0);
    this->setRowCount(line);
//    this->verticalHeader()->hide();
//    this->horizontalHeader()->hide();
    QStringList horizontalHeaderList;
    QStringList verticalHeaderList;
    //horizontal header
    for(int j=0;j<16;j++){
        horizontalHeaderList<<(QString("%1").arg(j,2,16));
        this->setColumnWidth(j,30);
    }
    horizontalHeaderList<<QString(" ");
    this->setColumnWidth(16,30);
    for(int j=0;j<16;j++){
        horizontalHeaderList<<(QString("%1").arg(j,2,16));
        this->setColumnWidth(j,30);
        this->setColumnWidth(j+16+1,20);
    }
    //vertical header
    for(int i=0;i<line;i++){
        verticalHeaderList<<(QString("%1").arg(i<<4,4,16));
    }
    setHorizontalHeaderLabels(horizontalHeaderList);
    setVerticalHeaderLabels(verticalHeaderList);
    int i;
    QTableWidgetItem *t;
    for(i=0;i<line-1;i++){
       for( int j=0;j<16;j++){
           t=new QTableWidgetItem(QString("%1").arg(p->pkt_data[i*16+j],2,16));
                   t->setFlags(t->flags()&~Qt::ItemIsEditable);
                   t->setTextAlignment(Qt::AlignCenter);
            this->setItem(i,j,t);

                   if(isprint(p->pkt_data[i*16+j])){
                       t=new QTableWidgetItem(QChar(p->pkt_data[i*16+j]));
                   }else{
                       t=new QTableWidgetItem(QChar('~'));
                   }
                   t->setFlags(t->flags()&~Qt::ItemIsEditable);
                   t->setTextAlignment(Qt::AlignCenter);
            this->setItem(i,j+16+1,t);
        }
    }
    if(i<line){//last line
        for( int j=0;j<len-i*16;j++){
            t=new QTableWidgetItem(QString("%1").arg(p->pkt_data[i>>4+j],2,16));
            t->setFlags(t->flags()&~Qt::ItemIsEditable);
            t->setTextAlignment(Qt::AlignCenter);
            this->setItem(i,j,t);

            if(isprint(p->pkt_data[i*16+j])){
                t=new QTableWidgetItem(QChar(p->pkt_data[i*16+j]));
            }else{
                t=new QTableWidgetItem(QChar('~'));
            }
            t->setFlags(t->flags()&~Qt::ItemIsEditable);
            t->setTextAlignment(Qt::AlignCenter);
     this->setItem(i,j+16+1,t);
        }
    }
}
