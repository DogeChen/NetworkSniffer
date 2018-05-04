#include "packet.h"

Packet::Packet(int Number,struct pcap_pkthdr *header,const u_char *pkt_data){
    this->Number=Number;
    this->header=header;
    char s[30];
    time_t t=((time_t)(header->ts.tv_sec));
//    struct tm t1;
//    localtime_s(&t1, &t);
//    strftime(s,sizeof(char),"%H:%M:%S",&t1);
//    this->time=QString("%1").arg(s);
        this->time=QString("%1").arg(ctime(&t));
    this->caplen=header->caplen;
    this->len=header->len;
    //todo fix this point
    this->pkt_data=pkt_data;

//    qDebug()<<"pkt_data"<<*pkt_data;
//    print_packet();
    parseAllProtocol();
}
void Packet::parseAllProtocol()
{
    ethernetHeader=new EthernetHeader(pkt_data);
    protocol=protocol.append("Eth");
    if(ethernetHeader->type==ARP_PROTOCOL){
//        qDebug()<<"arp:";
        parseNetworkLayerProtocol();
    }else if(ethernetHeader->type==IP_PROTOCOL){
//        qDebug()<<"ip:";
        parseNetworkLayerProtocol();
    }

}

void Packet::parseNetworkLayerProtocol()
{
    if(ethernetHeader->type==IP_PROTOCOL){
        if(pkt_data[14]>>4==0x4){//ipv4?
//            qDebug()<<"ip version = 4";
            networkHeader=new NetworkLayerIpv4Header(pkt_data+14);
//            ((NetworkLayerIpv4Header*)networkHeader)->toString();
            protocol=protocol.append("/IPv4");
            parseTransportLayerProtocol(IP_PROTOCOL);

        }else if(pkt_data[14]>>4==0x6){//ipv6?
//            qDebug()<<"ip version = 6";
            protocol=protocol.append("/IPv6");
            networkHeader=new NetworkLayerIpv6Header(pkt_data+14);
        }
//        qDebug()<<"ipv4:id="<<((NetworkLayerIpv4Header*)networkHeader)->id;
//        print_packet();
    }else if(ethernetHeader->type==ARP_PROTOCOL){
        networkHeader=new NetworkLayerArpHeader(pkt_data+14);
        protocol=protocol.append("/ARP");
        if(((NetworkLayerArpHeader*)networkHeader)->Operation==ARP_REPLY){
            protocol=protocol.append("(REPLY)");
        }else if(((NetworkLayerArpHeader*)networkHeader)->Operation==ARP_REQUEST){
            protocol=protocol.append("(REQUEST)");
        }
    }
}

void Packet::parseTransportLayerProtocol(int type)
{
    if(type==IP_PROTOCOL){
        NetworkLayerIpv4Header *nheader=(NetworkLayerIpv4Header*)networkHeader;
        int offset=14+nheader->headerLen*4;
        switch (nheader->upperProtocol) {
        case TCP_PROTOCOL:
            transportHeader=new TransportLayerTcpHeader(pkt_data+offset);
            protocol=protocol.append("/TCP");
//            ((TransportLayerTcpHeader*)transportHeader)->toString();
//            qDebug()<<"header len="<<offset+((TransportLayerTcpHeader*)transportHeader)->headerLen*4;
            parseApplicationLayerProtocol(offset+((TransportLayerTcpHeader*)transportHeader)->headerLen*4);
            break;
        case UDP_PROTOCOL:
            transportHeader=new TransportLayerUdpHeader(pkt_data+offset);
            protocol=protocol.append("/UDP");
            break;
        case ICMP_PROTOCOL:
            transportHeader=new TransportLayerIcmpHeader(pkt_data+offset);
            protocol=protocol.append("/ICMP");
        default:
            break;
        }
    }
}

void Packet::parseApplicationLayerProtocol(int offset)
{
    applicationHeader=ApplicationHeaderFactory::create(pkt_data+offset,len-offset);
    if(applicationHeader!=NULL){
        qDebug()<<"http packet";
        protocol.append("/HTTP");
    }
}

void Packet::print_packet()
{
//    int LINE_LEN=16;
//    /* print pkt timestamp and pkt len */
//    // qDebug()<<; //将结构中的信息转换为真实世界的时间，以字符串的形式显示
//    qDebug("%ld",len);
//    /* Print the packet */
//    for (int i=1; i < len + 1; i+=LINE_LEN)
//    {
//        qDebug("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
//               ,pkt_data[i-1],pkt_data[i],pkt_data[i+1],pkt_data[i+2]
//                ,pkt_data[i+3],pkt_data[i+4],pkt_data[i+5],pkt_data[i+6]
//                ,pkt_data[i+7],pkt_data[i+8],pkt_data[i+9],pkt_data[i+10]
//                ,pkt_data[i+11],pkt_data[i+12],pkt_data[i+13],pkt_data[i+14]);
//    }
}
