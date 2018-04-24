#include "packetfilter.h"
#include "ui_packetfilter.h"

PacketFilter::PacketFilter(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketFilter)
{
    ui->setupUi(this);
}

PacketFilter::~PacketFilter()
{
    delete ui;
}
