#ifndef PACKETFILTER_H
#define PACKETFILTER_H
#include "public_qt_header.h"
#include "public_header.h"
namespace Ui {
class PacketFilter;
}
enum PROTOCOLTYPE{
ARP,
TCP,
UDP,
ICMP
};

class PacketFilter : public QDialog
{
    Q_OBJECT


public:
    explicit PacketFilter(QWidget *parent = 0);
    ~PacketFilter();
    QString getFilter();
private:
    QString filter;

private slots:
    void on_Check_clicked();

    void on_TCP_stateChanged(int arg1);

    void on_UDP_stateChanged(int arg1);

    void on_ICMP_stateChanged(int arg1);

    void on_ARP_stateChanged(int arg1);

    void on_Clear_clicked();

    void on_okButton_clicked();

private:
    Ui::PacketFilter *ui;

    void stateChange(int arg1, PROTOCOLTYPE type);
};

#endif // PACKETFILTER_H
