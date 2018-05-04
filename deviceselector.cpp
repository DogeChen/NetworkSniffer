#include "deviceselector.h"
#include "ui_deviceselector.h"

DeviceSelector::DeviceSelector(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceSelector)
{
    ui->setupUi(this);
    setWindowTitle("Adapter Selector");
    showAllDevices();
}

DeviceSelector::~DeviceSelector()
{
    delete ui;
}

pcap_if_t *DeviceSelector::getChosenDevice()
{
    return this->chosenDevice;
}

void DeviceSelector::showAllDevices()
{
    pcap_if_t *c;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, errbuf) == -1)
    {
        qDebug()<<"Error in pcap_findalldevs_ex:"<<errbuf;
        return ;
    }
    int total_row=0;
    for(c=allDevices;c; c=c->next)
    {
        total_row++;
    }
    ui->Device_table->setRowCount(total_row);
    ui->Device_table->setColumnCount(2);
    QStringList header;header<<"网卡名"<<"网卡描述";    //表头
    ui->Device_table->setHorizontalHeaderLabels(header);

    int row=0;
    for(c=allDevices;c;c=c->next)
    {
        QString device_name=QString("%1").arg(c->name);
        QString device_description=QString("%1").arg(c->description);


        QTableWidgetItem * tp=new QTableWidgetItem(device_name);
        tp->setFlags(tp->flags() & ~Qt::ItemIsEditable);
        ui->Device_table->setItem(row,0,tp);

        if (!device_description.isNull())
        {
            QTableWidgetItem * tp1=new QTableWidgetItem(device_description.section("adapter ",1,1));
            tp1->setFlags(tp1->flags() & ~Qt::ItemIsEditable);

            ui->Device_table->setItem(row,1,tp1);
        }
        else
        {
            QTableWidgetItem * tp1=new QTableWidgetItem("(No description available)");
            tp1->setFlags(tp1->flags() & ~Qt::ItemIsEditable);
            ui->Device_table->setItem(row,1,tp1);
        }
        row++;
    }  


    ui->Device_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->Device_table->verticalHeader()->setSectionResizeMode(QHeaderView::Stretch);
//    ui->Device_table->horizontalHeader()->setSortIndicatorShown(true);
//    connect(ui->Device_table->horizontalHeader(),SIGNAL(sectionClicked(int)),
//            ui->Device_table,SLOT(sortByColumn(int)));

}

void DeviceSelector::on_Device_table_itemClicked(QTableWidgetItem *item)
{
    qDebug()<<item->row();
    chosenDevice=allDevices;
    for(int i=item->row();i>0&&chosenDevice!=NULL;i--){
        chosenDevice=chosenDevice->next;
    }
    if(chosenDevice==NULL){
        QMessageBox::warning(this,"警告！","程序出现位置错误！",QMessageBox::Yes);
        return;
    }
    qDebug()<<"chosenDevice:"<<chosenDevice->name<<chosenDevice->description;
    ui->Network_interface_card_name->setText(chosenDevice->name);
}

void DeviceSelector::on_Next_clicked()
{
    if(chosenDevice==NULL)
    {
        QMessageBox::warning(this,"警告！","未选择需要监听的网卡！",QMessageBox::Yes);
        return ;
    }
    else
    {
        this->accept();
    }
}

void DeviceSelector::on_Cancel_clicked()
{
    chosenDevice=NULL;
    ui->Network_interface_card_name->clear();
}
