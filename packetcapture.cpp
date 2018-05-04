#include "packetcapture.h"


PacketCapture::PacketCapture(pcap_if_t *device):QObject()
{
    workThread=new QThread;
    qDebug()<<this->thread()->objectName();
    workThread->setObjectName("PacketCaptureThread");
    workThread->start();
    this->moveToThread(workThread);
    chosenDevice=device;
    qDebug()<<"current thread"<<this->thread()->currentThread()->objectName();
}

void PacketCapture::setFilter(QString filter){
    this->filter=filter;
}

void PacketCapture::beginCapture()
{
//    while(true){
        qDebug()<<"beginCapture"<<"current thread"<<this->thread()->currentThread()->objectName();

        bpf_program bpf_filter;
        pcap_t *fp;
        u_int inum, i=0;
        char errbuf[PCAP_ERRBUF_SIZE];
        int res;

        bpf_u_int32 mask;
        bpf_u_int32 net;
        const char * filterStr=filter.toStdString().data();
        const char * deviceName=chosenDevice->name;
        struct pcap_pkthdr *header;
        const u_char *pkt_data;

        fp= pcap_open(deviceName,
                      65537 /*snaplen*/,
                      PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                      20 /*read timeout*/,
                      NULL /* remote authentication */,
                      errbuf);

        pcap_lookupnet(deviceName,
                       &net,
                       &mask,
                       errbuf);

        pcap_compile(fp,&bpf_filter,filterStr,1,net);
        if (pcap_setfilter(fp, &bpf_filter)<0)
        {
            qDebug()<<"Fail Setting filter！";
        }
        else
        {
            qDebug()<<"Success set filter ！";
        }

        /* Read the packets */
        while((res = pcap_next_ex( fp, &header, &pkt_data))>= 0&&!isStop)
        {
            if(res == 0) /* Timeout elapsed */
                continue;
    //        qDebug()<<"data"<<pkt_data;
            //make a copy of pkt_data
            int len=header->len;
            u_char * nPktData=new u_char[len];
            memcpy(nPktData,pkt_data,sizeof(u_char)*len);
            emit newPacket(header,nPktData);
        }
//        this->thread()->
//    }
}

void PacketCapture::stopCapture()
{
    //stop capture
    qDebug()<<"stop capture";
    disconnect(this,0,0,0);
    isStop=true;
//    workThread->deleteLater();
    qDebug()<<this->thread()->objectName();
}

