#include "packetfilter.h"
#include "ui_packetfilter.h"

PacketFilter::PacketFilter(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PacketFilter)
{
    ui->setupUi(this);
    setWindowTitle("Packet Filter");
}

PacketFilter::~PacketFilter()
{
    delete ui;
}

QString PacketFilter::getFilter()
{
    return filter;
}

void PacketFilter::on_Check_clicked()
{
    //get filter string
    filter=ui->inputFilterText->toPlainText();
    //check filter
//    pcap_if_t *chosen;
//    pcap_t *fp;
    int snaplen=65535;
    struct bpf_program filter;

    int net;
    if(pcap_compile_nopcap(snaplen,1,&filter,ui->inputFilterText->toPlainText().toStdString().data(),1,net)<0){
        QMessageBox::warning(this,"警告！","过滤器格式设置错误，请检查！",QMessageBox::Yes);
    }else{
        qDebug()<<"success!";
        QMessageBox::information(this,"提示","过滤器设置成功！",QMessageBox::Yes);
    }
}

void PacketFilter::on_TCP_stateChanged(int arg1)
{
    stateChange(arg1,PROTOCOLTYPE::TCP);
}


void PacketFilter::on_UDP_stateChanged(int arg1)
{
    stateChange(arg1,PROTOCOLTYPE::UDP);
}

void PacketFilter::on_ICMP_stateChanged(int arg1)
{
stateChange(arg1,PROTOCOLTYPE::ICMP);
}

void PacketFilter::on_ARP_stateChanged(int arg1)
{
    stateChange(arg1,PROTOCOLTYPE::ARP);
}

void PacketFilter::stateChange(int arg1,PROTOCOLTYPE type){
    QString typeStr;
    qDebug()<<arg1;

    switch (type) {
        case PROTOCOLTYPE::TCP:
            typeStr="tcp";
            break;
        case PROTOCOLTYPE::UDP:
            typeStr="udp";
            break;
        case PROTOCOLTYPE::ICMP:
            typeStr="icmp";
            break;
        case PROTOCOLTYPE::ARP:
            typeStr="arp";
        default:
            break;
    }
    qDebug()<<typeStr<<" is clicked";
    QString s=ui->inputFilterText->toPlainText();
    //todo fix this bug
    if(arg1==2){
        if(s!=""){
            ui->inputFilterText->setText(typeStr+" or \n"+s);
        }else{
            ui->inputFilterText->setText(typeStr+"\n");
        }
    }else{
        if(s.contains(typeStr+" or \n")){
            s=s.replace(typeStr+" or \n","");
        }else{
            s=s.replace(typeStr,"");
        }
    }
}

void PacketFilter::on_Clear_clicked()
{
    ui->inputFilterText->setText("");
    ui->TCP->setChecked(false);
    ui->UDP->setChecked(false);
    ui->ICMP->setChecked(false);
    ui->ARP->setChecked(false);
}

void PacketFilter::on_okButton_clicked()
{
    this->filter=ui->inputFilterText->toPlainText();
    this->accept();
}
