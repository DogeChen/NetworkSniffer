#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "public_header.h"
#include "public_qt_header.h"
#include "packet.h"
#include "packetcapture.h"
#include "packettree.h"
#include "packettable.h"
#include <QVBoxLayout>
#include <QWidget>
#include "deviceselector.h"
#include "packetfilter.h"
#include "packetdex.h"
#include "arpattacker.h"
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    PacketCapture *packetCapture=NULL;
    ~MainWindow();
private:
    PacketTable *pTable;
    PacketTree *pTree;
    PacketDex *pDex;
    pcap_if_t * chosenDevice=NULL;
    ArpAttacker *attacker=NULL;
    QString filterStr;

public:
    void createPacketCapture();
private:
    Ui::MainWindow *ui;
public slots:
    void newPacketIn(struct pcap_pkthdr *header,const u_char *pkt_data);

    void on_arpStart();
    void on_arpStop();
private slots:
    void on_setFilterButton_clicked();
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_restartButton_clicked();

    void on_chooseAdapterButton_clicked();
    void on_arpattacker_clicked();

    void on_saveButton_clicked();

    void on_closeButton_clicked();

    void on_reloadButton_clicked();

signals:
    void beginCapture();

};

#endif // MAINWINDOW_H
