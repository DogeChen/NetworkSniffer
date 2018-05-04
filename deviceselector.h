#ifndef DEVICESELECTOR_H
#define DEVICESELECTOR_H

#include <QWidget>
#include <QDialog>
#include <qDebug>
#include <QMessageBox>
#include <QTableWidgetItem>

#include "public_header.h"
namespace Ui {
class DeviceSelector;
}

class DeviceSelector : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceSelector(QWidget *parent = 0);
    ~DeviceSelector();
    pcap_if_t * getChosenDevice();
private:
    Ui::DeviceSelector *ui;
    void showAllDevices();
    pcap_if_t * chosenDevice,*allDevices;

private slots:
    void on_Device_table_itemClicked(QTableWidgetItem *item);
    void on_Next_clicked();
    void on_Cancel_clicked();
};

#endif // DEVICESELECTOR_H
