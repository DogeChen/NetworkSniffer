#ifndef PACKET_H
#define PACKET_H
#include "public_header.h"
#include "public_qt_header.h"
#include "Winsock2.h"

/* 网络层协议类型 */
#define IP_PROTOCOL       0x0800
#define ARP_PROTOCOL      0x0806
/* 传输层类型 */
#define ICMP_PROTOCOL       0x01
#define IGMP_PROTOCOL       0x02
#define TCP_PROTOCOL        0x06
#define UDP_PROTOCOL        0x11

#define IPv6_PROTOCOL       0x29

/*ARP协议opcode*/
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02


inline  void addItem(QTreeWidgetItem* item,QString str){
    item->addChild(new QTreeWidgetItem(QStringList(str)));
    return;
}
inline QString getIP(const u_char *ip){
    return QString("%1.%2.%3.%4").
            arg(ip[0],3,10,QChar(' ')).arg(ip[1],3,10,QChar(' ')).
            arg(ip[2],3,10,QChar(' ')).arg(ip[3],3,10,QChar(' '));
}
inline QString getIPv6(const u_short *ip){
    return QString("%1.%2.%3.%4.%5.%6.%7.%8").
            arg(ip[0],4,16,QChar('0')).arg(ip[1],4,16,QChar('0')).
            arg(ip[2],4,16,QChar('0')).arg(ip[3],4,16,QChar('0')).
            arg(ip[4],4,16,QChar('0')).arg(ip[5],4,16,QChar('0')).
            arg(ip[6],4,16,QChar('0')).arg(ip[7],4,16,QChar('0'));
}

inline QString getMac(u_char* mac){
    return QString("%1.%2.%3.%4.%5.%6")
            .arg(mac[0],2,16,QChar('0'))
            .arg(mac[1],2,16,QChar('0'))
            .arg(mac[2],2,16,QChar('0'))
            .arg(mac[3],2,16,QChar('0'))
            .arg(mac[4],2,16,QChar('0'))
            .arg(mac[5],2,16,QChar('0'));
}




struct NetworkLayerHeader{
public:
    NetworkLayerHeader(){

    }
public :
    virtual QTreeWidgetItem* getTreeWidgetItems()=0;
    virtual ~NetworkLayerHeader(){
    }
    virtual QString getSrcIP()=0;
    virtual QString getDesIP()=0;
};
struct NetworkLayerArpHeader:public NetworkLayerHeader{
    u_short hardwareType,protocolType;
    //Hardware address length (HLEN)
    //    Protocol address length
    u_char HLEN,PLEN;
    u_short Operation;
    u_char senderMAC[6],senderAddress[4],
    targetMAC[6],targetAddress[4];
public :
    NetworkLayerArpHeader(){

    }

public:
    NetworkLayerArpHeader(const u_char *d):NetworkLayerHeader(){
        memcpy(&hardwareType,d,sizeof(u_short));
        memcpy(&protocolType,d+2,sizeof(u_short));
        HLEN=d[4],PLEN=d[5];
        memcpy(&Operation,d+6,sizeof(u_short));
        memcpy(senderMAC,d+8,sizeof(u_char)*6);
        memcpy(senderAddress,d+14,sizeof(u_char)*4);
        memcpy(targetMAC,d+18,sizeof(u_char)*6);
        memcpy(targetAddress,d+24,sizeof(u_char)*4);
        hardwareType=ntohs(hardwareType);
        protocolType=ntohs(protocolType);
        Operation=ntohs(Operation);
    }
    virtual QTreeWidgetItem * getTreeWidgetItems(){
       QTreeWidgetItem *t=new QTreeWidgetItem(QStringList(QString("ARP")));
       addItem(t,QString("HELN : %1").arg(HLEN));
       addItem(t,QString("PELN : %1").arg(PLEN));
       addItem(t,QString("Operation : %1").arg(Operation));
       addItem(t,QString("sender MAC : %1").arg(getMac(senderMAC)));
       addItem(t,QString("sender IP : %1").arg(getIP(senderAddress)));
       addItem(t,QString("target MAC : %1").arg(getMac(targetMAC)));
       addItem(t,QString("target IP : %1").arg(getIP(targetAddress)));
       return t;
    }
   virtual QString getSrcIP(){
        return getIP(senderAddress);
    }
   virtual QString getDesIP(){
        return getIP(targetAddress);
    }
};
struct NetworkLayerIpv4Header:public NetworkLayerHeader{
public:
    NetworkLayerIpv4Header(const u_char * data):NetworkLayerHeader(){
        version=data[0]>>4&0xff;
        headerLen=data[0]&0xff;
        TOS=data[1];
        memcpy((void *)&totalLen,data+2,sizeof(u_short));
        memcpy((void *)&id,data+4,sizeof(u_short));
        // net to host
        totalLen=ntohs(totalLen);
        id      =ntohs(id);
        u_short temp;
        memcpy((void *)&temp,data+6,sizeof(u_short));
        temp=ntohs(temp);
        flag=temp>>13;
        offset=temp;
        TTL=data[8];
        upperProtocol=data[9];

        memcpy((void *)&checkSum,data+10,sizeof(u_short));
        checkSum=ntohs(checkSum);

        memcpy(sourceAddress,data+12,sizeof(u_char)*4);
        memcpy(destinationAddress,data+16,sizeof(u_char)*4);
        int len=headerLen-20;
        if(len>0){
            op=new u_char[len];
            memcpy(op,data+20,len*sizeof(u_char));
        }else{
            op=NULL;
        }
    }
   virtual QString getDesIP(){
        return getIP(destinationAddress);
    }
    virtual QString getSrcIP(){
        return getIP(sourceAddress);
    }
public:
//    QString toString(){
//        qDebug("sou ip %d.%d.%d.%d",sourceIp[0],sourceIp[1],sourceIp[2],sourceIp[3]);
//        qDebug("des ip %d.%d.%d.%d",destinationIp[0],destinationIp[1],
//                destinationIp[2],destinationIp[3]);

//        return NULL;
//        }
    virtual QTreeWidgetItem* getTreeWidgetItems(){

        QTreeWidgetItem *item=new QTreeWidgetItem(QStringList(QString("IPv4")));
        QStringList* l=new QStringList();
        item->addChild(new QTreeWidgetItem(QStringList(QString("version : 0x%1").arg(version))));
        item->addChild(new QTreeWidgetItem(QStringList(QString("header length : %1*4bytes").arg(headerLen))));
        item->addChild(new QTreeWidgetItem(QStringList((QString("TOS : %1").arg(TOS)))));
        item->addChild(new QTreeWidgetItem(QStringList((QString("total length : %1").arg(totalLen)))));
        item->addChild(new QTreeWidgetItem(QStringList((QString("id : %1").arg(id)))));
        QTreeWidgetItem * t=new QTreeWidgetItem(QStringList((QString("flag : %1b").arg(flag,3,2))));
        t->addChild(new QTreeWidgetItem(QStringList(QString("DF : %1").arg(flag>>1&0x1,1,2))));
        t->addChild(new QTreeWidgetItem(QStringList(QString("MF : %1").arg(flag&0x1,1,2))));
        item->addChild(t);
        item->addChild(new QTreeWidgetItem(QStringList(QString("offset : %1").arg(offset))));
        item->addChild(new QTreeWidgetItem(QStringList(QString("TTL : %1").arg(TTL))));
        QString s=QString("protocol : %1(0x%2)");
        switch (upperProtocol) {
        case TCP_PROTOCOL:
            s=s.arg("TCP").arg(upperProtocol,2,16);
            break;
        case UDP_PROTOCOL:
            s=s.arg("UDP").arg(upperProtocol,2,16);
            break;
        case ICMP_PROTOCOL:
            s=s.arg("ICMP").arg(upperProtocol,2,16);
            break;
        default:
            s=s.arg("Unknown").arg(upperProtocol,2,16);
            break;
        }
        item->addChild(new QTreeWidgetItem(QStringList(s)));
        item->addChild(new QTreeWidgetItem(QStringList(QString("CheckSum : 0x%1").arg(checkSum,4,16))));
        item->addChild(new QTreeWidgetItem(QStringList(QString("Destination IP : %1").arg(this->getDesIP()))));
        item->addChild(new QTreeWidgetItem(QStringList(QString("Source IP : %1").arg(this->getSrcIP()))));
        s=QString("option : %1");
        if(op==NULL){
            s=s.arg("NULL");
        }else{

            s=s.arg(QString("length=%1").arg(totalLen-20));
        }
        item->addChild(new QTreeWidgetItem(QStringList(s)));
        return item;
    }
public:
    u_char version:4,headerLen:4;
    u_char TOS;
    u_short totalLen;//len of header and data
    u_short id;
    u_short flag:3,offset:13;
    u_char TTL;
    u_char upperProtocol;
    u_short checkSum;
    u_char sourceAddress[4],destinationAddress[4];
    u_char *op;//optional,length depends on headerLen
    virtual ~NetworkLayerIpv4Header(){
        if(op!=NULL){
            delete op;
            op=NULL;
        }
    }
};
struct NetworkLayerIpv6Header:public NetworkLayerHeader{
public :
    u_int32_t version:4,TOS:8,flowLabel:20;
    u_short payloadLength;
    u_char nextHeader,hopLimit;
    u_short sourceAddress[8],destinationAddress[8];
    virtual QTreeWidgetItem * getTreeWidgetItems(){
        QTreeWidgetItem * item=new QTreeWidgetItem(QStringList(QString("IPv6")));
        item->addChild(new QTreeWidgetItem(QStringList(QString("Version : 0x%1").arg(version))));
        item->addChild(new QTreeWidgetItem(QStringList((QString("TOS : %1").arg(TOS)))));
        item->addChild(new QTreeWidgetItem(QStringList((QString("Flow Label : %1").arg(flowLabel)))));

        item->addChild(new QTreeWidgetItem(QStringList((QString("Payload Length : %1").arg(payloadLength)))));
        QString s=QString("Next Header : %1(0x%2)");

        if(nextHeader==TCP_PROTOCOL){s=s.arg("TCP");
        }else if(nextHeader==UDP_PROTOCOL){ s=s.arg("UDP");
        }else{ s=s.arg("Unknown");}
        s=s.arg(nextHeader,2,16,QChar('0'));
        item->addChild(new QTreeWidgetItem(QStringList(s)));
        item->addChild(new QTreeWidgetItem(QStringList(QString("Hop Limit: %1").arg(hopLimit))));

        return item;
    }
    NetworkLayerIpv6Header(const u_char * data):NetworkLayerHeader(){
        u_int32_t temp;
        memcpy(&temp,data,sizeof(u_int32_t));
        temp=ntohl(temp);
        version=temp>>28&0xf;
        TOS=temp>>20&0xff;
        flowLabel=temp&0xfffff;
        memcpy(&payloadLength,data+4,sizeof(u_short));
        payloadLength=ntohs(payloadLength);
        nextHeader=data[6];
        hopLimit=data[7];
        memcpy(sourceAddress,data+8,8*sizeof(u_short));
        memcpy(destinationAddress,data+24,8*sizeof(u_short));
        for(int i=0;i<8;i++){
            sourceAddress[i]=ntohs(sourceAddress[i]);
            destinationAddress[i]=ntohs(destinationAddress[i]);
        }
    }
    virtual QString getDesIP(){
        return getIPv6(destinationAddress);
    }
    virtual QString getSrcIP(){
        return getIPv6(sourceAddress);
    }

};
struct TransportLayerHeader{
    virtual ~TransportLayerHeader(){
    }
    virtual QTreeWidgetItem* getTreeWidgetItems()=0;
};
struct TransportLayerIcmpHeader:public TransportLayerHeader{
public:
    u_char type;            //8位 类型
    u_char code;            //8位 代码
    u_short checkSum;      //8位校验和
    u_short flag;       //标识符
    u_short seq;         //序列号 8位
public :
    TransportLayerIcmpHeader(const u_char * data){
        type=data[0];
        code=data[1];
        memcpy((void *)&checkSum,data+2,sizeof(u_short));
        memcpy((void *)&flag,data+4,sizeof(u_short));
        memcpy((void*)&seq,data+6,sizeof(u_short));
        checkSum=ntohs(checkSum);
        flag=ntohs(flag);
        seq=ntohs(seq);
    }
    virtual QTreeWidgetItem * getTreeWidgetItems(){
         QTreeWidgetItem * item=new QTreeWidgetItem(QStringList(QString("ICMP")));
         switch(type){
         case 0:

             addItem(item,QString("type : %1").arg("Echo Reply"));
             break;
         case 8:
             addItem(item,QString("type : %1").arg("Echo"));
             break;
         default:

             addItem(item,QString("type : %1").arg(type));
             break;
         }

         addItem(item,QString("code : %1").arg(code));
         addItem(item,QString("checkSum : %1").arg(checkSum));
         addItem(item,QString("flag : %1").arg(flag));
         addItem(item,QString("sequence : %1").arg(seq));
         return item;
    }
};
struct TransportLayerUdpHeader:public TransportLayerHeader{
public:
    u_short desPort,srcPort;
    u_short len,checkSum;
    TransportLayerUdpHeader(const u_char *data):TransportLayerHeader(){
        memcpy((void*)&desPort,data,sizeof(u_short));
        memcpy((void*)&srcPort,data+2,sizeof(u_short));
        memcpy((void*)&len,data+4,sizeof(u_short));
        memcpy((void*)&checkSum,data+6,sizeof(u_short));

        desPort=ntohs(desPort);
        srcPort=ntohs(srcPort);
        len=ntohs(len);
        checkSum=ntohs(checkSum);
    }
    virtual QTreeWidgetItem * getTreeWidgetItems(){
        QTreeWidgetItem * item=new QTreeWidgetItem(QStringList(QString("UDP")));
        addItem(item,QString("destination port : %1").arg(desPort));
        addItem(item,QString("source port : %1").arg(srcPort));
        addItem(item,QString("length : %1").arg(len));
        addItem(item,QString("CheckSum : %1").arg(checkSum));
        return item;
    }
};
struct TransportLayerTcpHeader:public TransportLayerHeader{
public:
    u_short desPort,srcPort;
    u_int32_t seqNum,ackNum;
    u_short headerLen:4,reserve:6
            ,URG:1,ACK:1,PSH:1,RST:1,SYN:1,FIN:1;
    u_short window;
    u_short checkSum,urgeDataPoint;
    u_int32_t* op;
    TransportLayerTcpHeader(const u_char *data):TransportLayerHeader(){
        memcpy((void*)&desPort,data,sizeof(u_short));
        memcpy((void*)&srcPort,data+2,sizeof(u_short));
        desPort=ntohs(desPort);
        srcPort=ntohs(srcPort);
        memcpy((void*)&seqNum,data+4,sizeof(u_int32_t));
        memcpy((void*)&ackNum,data+8,sizeof(u_int32_t));
        seqNum=ntohl(seqNum);
        ackNum=ntohl(ackNum);
        u_short temp;
        memcpy((void*)&temp,data+12,sizeof(u_short));
        temp=ntohs(temp);
        headerLen=temp>>12&(0xf);
        reserve=temp>>6&(0x3f);
        URG=temp>>5&0x1,ACK=temp>>4&0x1,PSH=temp>>3&0x1,RST=temp>>2&0x1,SYN=temp>>1&0x1,FIN=temp&0x1;

        memcpy((void*)&window,data+14,sizeof(u_short));
        memcpy((void*)&checkSum,data+16,sizeof(u_short));
        memcpy((void*)&urgeDataPoint,data+18,sizeof(u_short));
        window=ntohs(window),checkSum=ntohs(checkSum),urgeDataPoint=ntohs(urgeDataPoint);
        if(headerLen>5){
            int len=headerLen-5;
            op=new u_int32_t[len];
            memcpy((void*)op,data+20,len*sizeof(u_int32_t));
        }else{
            op=NULL;
        }
    }
    QString toString(){
        qDebug("tcp");
        qDebug("des port:%d src port:%d",desPort,srcPort);
        qDebug("seqNum %d ackNum %d",seqNum,ackNum);
        return NULL;
    }
    virtual QTreeWidgetItem* getTreeWidgetItems(){
        QTreeWidgetItem* item=new QTreeWidgetItem(QStringList(QString("TCP")));
        addItem(item,QString("destination port : %1").arg(desPort));
        addItem(item,QString("source port : %1").arg(srcPort));
        
        addItem(item,QString("seqence number : %1").arg(seqNum));
        addItem(item,QString("ack number : %1").arg(ackNum));
        addItem(item,QString("header length : %1").arg(headerLen));
        QTreeWidgetItem * t=new QTreeWidgetItem(QStringList(QString("保留字：%1B").arg(reserve,2,6)));
        addItem(t,QString("URG:%1").arg(URG));
        addItem(t,QString("ACK:%1").arg(ACK));
        addItem(t,QString("PSH:%1").arg(PSH));
        addItem(t,QString("RST:%1").arg(RST));
        addItem(t,QString("SYN:%1").arg(SYN));
        addItem(t,QString("FIN:%1").arg(FIN));
        item->addChild(t);
        addItem(item,QString("window size : %1").arg(window));
        addItem(item,QString("CheckSum : %1").arg(checkSum));
        addItem(item,QString("urge data point : %1").arg(urgeDataPoint));
        if(op==NULL){
            addItem(item,QString("option : NULL"));

        }else{
            addItem(item,QString("option : %1").arg(4*headerLen-20));
        }
        return item;
    }
};

struct EthernetHeader{
public:
    EthernetHeader(const u_char *pkt_data){
        memcpy(desMac,pkt_data,sizeof(u_char)*6);
        memcpy(srcMac,pkt_data+6,sizeof(u_char)*6);
        memcpy((void*)&type,pkt_data+12,sizeof(u_short));
        type=ntohs(type);
    }
public:
    EthernetHeader(){

    }
    EthernetHeader(u_char desMac[6],u_char srcMac[6],u_short type){
        memcpy(this->desMac,desMac,sizeof(u_char)*6);
        memcpy(this->srcMac,srcMac,sizeof(u_char)*6);
        this->type=type;
    }
public:
    u_char desMac[6];
    u_char srcMac[6];
    u_short type;
public:

    QString getDesMac(){
        return getMac(desMac);
    }
    QString getSrcMac(){
        return getMac(srcMac);
    }
    QString getType(){
        QString str;
        switch (type) {
        case IP_PROTOCOL:
            str=QString("IP(0x%1)").arg(type,4,16);
            break;
        case ARP_PROTOCOL:
            str=QString("ARP(0x%1)").arg(type,4,16);
            break;
        default:
            str=QString("Unknown(0x%1)").arg(type,4,16);
            break;
        }
        return str;
    }
    QTreeWidgetItem *getQTreeWidgetItem(){
         QTreeWidgetItem* t=new QTreeWidgetItem(QStringList(QString("Ethernet")));
         t->addChild(new QTreeWidgetItem(QStringList(QString("type : %1").arg(getType()))));
         t->addChild(new QTreeWidgetItem(QStringList(QString("destinatin mac : %1").arg(getDesMac()))));
         t->addChild(new QTreeWidgetItem(QStringList(QString("source mac : %1").arg(getSrcMac()))));
         return t;
    }
};
class ApplicationHeaderLayer{
public:
    virtual  QTreeWidgetItem *getTreeWidgetItem()=0;
};



class ApplicationHttpRequestHeaderLayer:public ApplicationHeaderLayer{
private:
//    static QRegularExpressionMatch re("(GET|POST) (\\w+) (HTTP)");
    QString method,url,version;
    QList<QPair<QString,QString>> headerLines;
    QString entity;

public:
    ApplicationHttpRequestHeaderLayer(const char *data):ApplicationHeaderLayer(){
        //assume http no contain '\0' as this is text
        QString dataStr=QString("%1").arg(data);
        delete data;
        data=NULL;
        int i=dataStr.indexOf("\r\n\r\n");
        QString headerStr=dataStr.left(i);
        QStringList t=headerStr.split(QString("\r\n"));
        QStringList t1=t.at(0).split(QRegExp("\\s"));
        method=t1.at(0),url=t1.at(1),version=t1.at(2);
        headerLines.clear();
        for(int j=1;j<t.size();j++){
            t1=t.at(j).split(QRegExp("\\s"));
            headerLines.append(QPair<QString,QString>(t1[0],t1[1]));
        }
        entity=dataStr.right(i+4);

    }
     virtual QTreeWidgetItem *getTreeWidgetItem(){
        QTreeWidgetItem* t=new QTreeWidgetItem(QStringList(version));
        addItem(t,QString("method:%1").arg(method));
        addItem(t,QString("url:%1").arg(url));
        addItem(t,QString("version:%1").arg(version));
        QTreeWidgetItem *h=new QTreeWidgetItem(QStringList(QString("header lines")));
        for(QPair<QString,QString> p:headerLines){
            addItem(h,QString("%1:%2").arg(p.first).arg(p.second));
        }
        t->addChild(h);
        h=new QTreeWidgetItem(QStringList(QString("entity")));
        addItem(h,entity);
        t->addChild(h);
        return t;
     }

public :
    static bool check(const u_char *data,int len){
        len=len>400?400:len;
        char mo[401];
        for(int i=0;i<len;i++){
            mo[i]=data[i];
        }
        mo[len]=0;
        QString mothed(mo);
        if(mothed.indexOf("\r\n\r\n")<0){
            return false;
        }
        qDebug()<<"header mo"<<mo;
        int i=mothed.indexOf(QString("\r\n"));
        if(i<0){
            return false;
        }
        QStringList l;

         l<<QString("POST")<<QString("GET")<<QString("PUT")<<QString("DELETE")<<QString("HEAD");

        mothed=mothed.left(i);
        for(QString i:l){
            if(mothed.indexOf(i,0,Qt::CaseInsensitive)==0){
                return true;
            }
        }
        return false;
    }
};

class ApplicationHttpResponseHeaderLayer:public ApplicationHeaderLayer{
private:
    static QRegularExpressionMatch matcher();
    QString version;
    int statusCode;
    QString shortStr;
    QList<QPair<QString,QString>> headerLines;
    QString entity;
public:
    ApplicationHttpResponseHeaderLayer(const char *data):ApplicationHeaderLayer(){
        QString dataStr=QString("%1").arg(data);//assume http no contain '\0' as this is text
        delete data;
        data=NULL;
        int i=dataStr.indexOf("\r\n\r\n");
        QString headerStr=dataStr.left(i);
        QStringList t=headerStr.split(QString("\r\n"));
        QStringList t1=t.at(0).split(QRegExp("\\s"));
        version =t1.at(0),statusCode=t1.at(1).toInt(),shortStr=t1.at(2);
        for(int j=1;j<t.size();j++){
            t1=t.at(j).split(QRegExp("\\s"));
            headerLines.append(QPair<QString,QString>(t1[0],t1[1]));
        }
        entity=dataStr.right(i+4);

    }
     virtual QTreeWidgetItem *getTreeWidgetItem(){
        QTreeWidgetItem* t=new QTreeWidgetItem(QStringList(version));
        addItem(t,QString("version:%1").arg(version));
        addItem(t,QString("statusCode:%1 %2").arg(statusCode).arg(shortStr));
        QTreeWidgetItem *h=new QTreeWidgetItem(QStringList(QString("header lines")));
        for(QPair<QString,QString> p:headerLines){
            addItem(h,QString("%1:%2").arg(p.first).arg(p.second));
        }
        t->addChild(h);
        h=new QTreeWidgetItem(QStringList(QString("entity")));
        addItem(h,entity);
        t->addChild(h);
        return t;
     }

public :
    static bool check(const u_char *data,int len){
        len=len>400?400:len;
        char mo[401];
        for(int i=0;i<len;i++){
            mo[i]=data[i];
        }
        mo[len-1]=0;
        QString mothed(mo);
        if(mothed.indexOf("\r\n\r\n")<0){
            return false;
        }
        qDebug()<<"header mo"<<mo;
        int i=mothed.indexOf(QString("\r\n"));
        if(i<0){
            return false;
        }
        mothed=mothed.left(i);
        if(mothed.indexOf(QString("HTTP"),0,Qt::CaseInsensitive)==0){
            return true;
        }else{
            return false;
        }
    }
};
class ApplicationHeaderFactory{
public :
    static ApplicationHeaderLayer* create(const u_char * data,int len){

        if(ApplicationHttpRequestHeaderLayer::check(data,len)){
            char *d=new char[len+1];
            memcpy(d,data,len);
            d[len]='\0';
            return new ApplicationHttpRequestHeaderLayer(d);
        }else if(ApplicationHttpResponseHeaderLayer::check(data,len)){
            char *d=new char[len+1];
            memcpy(d,data,len);
            d[len]='\0';
            return new ApplicationHttpResponseHeaderLayer(d);
        }else{
            return NULL;
        }
    }
};


//fix this bad extends in Packet
//better one is make Packet as a Parent ,and others extends this

class Packet
{
public:
    Packet(int Number, pcap_pkthdr *header,const u_char *pkt_data);
protected:
    Packet();

public:
    int Number;//number
    const u_char * pkt_data;//content
    pcap_pkthdr *header;
    QString time;//packet time
    bpf_u_int32 caplen,len;//packet len,len

    QString protocol;//protocol name

    int TransportLayerType;
    EthernetHeader *ethernetHeader=NULL;
    //link layer header
    NetworkLayerHeader* networkHeader=NULL;
    //transmission layer header
    TransportLayerHeader * transportHeader=NULL;
    ApplicationHeaderLayer *applicationHeader=NULL;
public:
    void parseAllProtocol();
    void parseNetworkLayerProtocol();
    void parseTransportLayerProtocol(int type);
    void parseApplicationLayerProtocol(int offset);
    void print_packet();
};


#endif // PACKET_H
