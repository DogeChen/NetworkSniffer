#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H
#include "public_header.h"
#include "public_qt_header.h"
#include "QThread"
class PacketCapture:public QObject
{
    Q_OBJECT
public:
    PacketCapture(pcap_if_t *device);
    void setFilter(QString filter);
private:
    pcap_if_t *chosenDevice;

    QString adapterName;
    QString filter;
    QThread *workThread;
    volatile bool isStop=false;
public slots:
    void beginCapture();
    void stopCapture();
signals:
    void newPacket(struct pcap_pkthdr *header,const u_char *pkt_data);
};

#endif // PACKETCAPTURE_H
