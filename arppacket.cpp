#include "arppacket.h"
#include "packet.h"
#include "public_header.h"
#include "public_qt_header.h"


ArpPacket::ArpPacket( const u_char * sourceMAC,const u_char *sourceIP
                     ,const u_char *targetIP)
{

    memset(d,0xff,sizeof(u_char)*6);// broadcast
//    memcpy(d,targetMAC,sizeof(u_char)*6);
    memcpy(d+6,sourceMAC,sizeof(u_char)*6);
    u_short t;
    t=ntohs(ARP_PROTOCOL);
    memcpy(d+12,&t,sizeof(u_short));
    t=ntohs(1);
    memcpy(d+14,&t,sizeof(u_short));

    t=ntohs(IP_PROTOCOL);
    memcpy(d+16,&t,sizeof(u_short));
    d[18]=6;//mac len 6,ip len 4
    d[19]=4;
    t=ntohs(ARP_REPLY);
    memcpy(d+20,&t,sizeof(u_short));
    memcpy(d+22,sourceMAC,sizeof(u_char)*6);
    memcpy(d+28,sourceIP,sizeof(u_char)*4);
    //is target mac =0?
    memset(d+32,0x0,sizeof(u_char)*6);
//    memcpy(d+32,targetMAC,sizeof(u_char)*6);
    memcpy(d+38,targetIP,sizeof(u_char)*4);
    if(PADDING>0){
        memset(d+42,0x0,6*sizeof(u_char));
        memset(d+48,0x8,12*sizeof(u_char));
//        memset(d+42,0xFF,PADDING*sizeof(u_char));
    }
    //todo 多线程，地址设置
}
