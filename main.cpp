#include "mainwindow.h"
#include <QApplication>
#include <pcap.h>
#include <qDebug>
#include <iostream>
#include <deviceselector.h>
#include <QDialog>
#include "packetfilter.h"
#include "packetcapture.h"
#define LINE_LEN 16
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow *w=new MainWindow();
    w->show();
    a.exec();
    return 0;
}
