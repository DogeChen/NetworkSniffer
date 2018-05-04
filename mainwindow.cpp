#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    pTable=new PacketTable;

    ui->vSplitter->addWidget(pTable);

    pTree=new PacketTree;

    ui->vSplitter->addWidget(pTree);
    pDex=new PacketDex;
    ui->vSplitter->addWidget(pDex);
    //connect table and tree
    connect(pTable,SIGNAL(onPacketClickedSignal(Packet*)),
            pTree,SLOT(setPacket(Packet*)));
    connect(pTable,SIGNAL(onPacketClickedSignal(Packet*)),
            pDex,SLOT(setPacket(Packet*)));
    connect(ui->actionstartARP,SIGNAL(changed()),
            this,SLOT(on_arpStart()));
    connect(ui->actionstopARP,SIGNAL(changed()),
            this,SLOT(on_arpStop()));

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::createPacketCapture()
{
    if(chosenDevice==NULL){
        QMessageBox::warning(this,QString("warning"),QString("have not chosen a network adapter!"),QMessageBox::Yes);
        return ;
    }
    packetCapture=new PacketCapture(chosenDevice);
    packetCapture->setFilter(filterStr);

    connect(packetCapture,SIGNAL(newPacket(pcap_pkthdr*, const u_char*))
            ,this,SLOT(newPacketIn(pcap_pkthdr*, const u_char*)));
//    packetCapture->beginCapture();
    connect(this,SIGNAL(beginCapture()),
            packetCapture,SLOT(beginCapture()));
    emit beginCapture();
    qDebug("start capture");
}

void MainWindow::newPacketIn(pcap_pkthdr *header, const u_char *pkt_data)
{
    Packet* p=new Packet(0,header,pkt_data);
    pTable->newPacketIn(p);
}

void MainWindow::on_setFilterButton_clicked()
{
    PacketFilter *f=new PacketFilter;
    if(f->exec()!=QDialog::Accepted){
        return ;
    }else{
        filterStr=f->getFilter();
        qDebug()<<"filter"<<filterStr;
        ui->filterTextLabel->setText(filterStr);
    }
}

void MainWindow::on_startButton_clicked()
{
    if(packetCapture==NULL){
        createPacketCapture();
    }else{
        qDebug()<<"has started,do nothing";
    }
}

void MainWindow::on_stopButton_clicked()
{
    if(packetCapture==NULL){
         qDebug()<<"has stopped,do nothing";
    }else{
        packetCapture->stopCapture();
//        delete packetCapture;
        packetCapture=NULL;
    }
}

void MainWindow::on_restartButton_clicked()
{
    on_stopButton_clicked();
    on_startButton_clicked();
}

void MainWindow::on_closeButton_clicked()
{
    pTable->clearPackets();
    pTree->clear();
    pDex->clear();

}

void MainWindow::on_chooseAdapterButton_clicked()
{
    //test module
    DeviceSelector *d=new DeviceSelector;
    if(d->exec()!=QDialog::Accepted){
       return ;
    }else{
        chosenDevice=d->getChosenDevice();
        ArpAttacker *a=new ArpAttacker;
       a->setAdapter(chosenDevice);
        ui->adapterName->setText(chosenDevice->name);
    }
}

void MainWindow::on_arpStart()
{
    if(chosenDevice==NULL){
        QMessageBox::warning(this,QString("warning"),QString("have not chosen a network adapter!"),QMessageBox::Yes);
        return ;
    }
    attacker=new ArpAttacker;
    attacker->setAdapter(chosenDevice);
    attacker->show();
}

void MainWindow::on_arpStop()
{
    attacker->onStop();
}

void MainWindow::on_arpattacker_clicked()
{
    on_arpStart();
}

void MainWindow::on_saveButton_clicked()
{
    QVector<Packet*>packets= pTable->packets;
    QDir dir("./packets/");
    if(!dir.exists()){
        QDir::current().mkdir("./packets");
    }
    for(int i=0;i<packets.size();i++){
        QFile file(QString("./packets/%1.p").arg(i+1));
        file.open(QIODevice::Truncate|QIODevice::ReadWrite);
        Packet *p=packets.at(i);
        file.write((char *)&(p->header->ts.tv_sec),sizeof(long));
        file.write((char *)&(p->header->len),sizeof(bpf_u_int32));
        file.write((char *)&(p->header->caplen),sizeof(bpf_u_int32));
        file.write(reinterpret_cast<const char *>(packets.at(i)->pkt_data),packets.at(i)->len);
        file.close();
    }
}

void MainWindow::on_reloadButton_clicked()
{
    QDir dir("./packets/");
    if(!dir.exists()){
        return;
    }
    for(int i=0;i<5000;i++){
        QFile file(QString("./packets/%1.p").arg(i+1));
        if(file.exists()){
            file.open(QIODevice::ReadOnly);
            int size=file.size();
            pcap_pkthdr *p=new pcap_pkthdr;
            uchar *data=new uchar[size-sizeof(long)-2*sizeof(bpf_u_int32)];
            file.read((char*)&(p->ts.tv_sec),sizeof(long));
            file.read((char *)&(p->len),sizeof(bpf_u_int32));
            file.read((char *)&(p->caplen),sizeof(bpf_u_int32));
            file.read(reinterpret_cast<char *>(data),size-sizeof(long)-2*sizeof(bpf_u_int32));
            emit newPacketIn(p,data);
            file.close();
        }else{
            break;
        }
    }
}
