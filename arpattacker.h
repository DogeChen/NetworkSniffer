#ifndef ARPATTACKER_H
#define ARPATTACKER_H

#include <QWidget>
#include <public_header.h>
#include <public_qt_header.h>
#include "arppacket.h"
#define MAC_LEN 6		// MAC 地址, 128 bits = 6 bytes
#define IPV4_LEN 4		// IPV4 地址, 32 bits = 4 bytes
#define PADDING_LEN 18		// ARP 数据包的有效载荷长度

namespace Ui {
class ArpAttacker;
}

class ArpAttacker : public QWidget
{
    Q_OBJECT
public:

    explicit ArpAttacker(QWidget *parent = 0);
    ~ArpAttacker();
    void setAdapter(pcap_if_t * t);
public slots:
    void onStop();

private slots:
    void on_startButton_clicked();
    void startAttack();

private:
  volatile  bool isContinue=true;
//    QThread *workThread=NULL;
    Ui::ArpAttacker *ui;
    bool checkInput();
    pcap_if_t * chosenAdapter;
    u_char myMAC[6];
    u_char gatewayMAC[6]={0x00,0x74,0x9c,0x7d,0xfc,0x93};
    u_char targetMAC[6]={0xF0,0x76,0x1c,0xce,0xe4,0xa7};
    u_char gatewayIP[4]={222,20,105,254};
    u_char targetIP[4]={222,20,104,133};
    ArpPacket *p1=NULL,*p2=NULL;
    bool getSelfInfo();
};

#endif // ARPATTACKER_H
