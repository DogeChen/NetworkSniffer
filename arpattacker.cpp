#include "arpattacker.h"
#include "ui_arpattacker.h"

ArpAttacker::ArpAttacker(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ArpAttacker)
{
    ui->setupUi(this);
}

ArpAttacker::~ArpAttacker()
{
    delete ui;
}
