#include "deviceselector.h"
#include "ui_deviceselector.h"

DeviceSelector::DeviceSelector(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::DeviceSelector)
{
    ui->setupUi(this);
}

DeviceSelector::~DeviceSelector()
{
    delete ui;
}
