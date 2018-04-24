#ifndef PACKETFILTER_H
#define PACKETFILTER_H

#include <QWidget>

namespace Ui {
class PacketFilter;
}

class PacketFilter : public QWidget
{
    Q_OBJECT

public:
    explicit PacketFilter(QWidget *parent = 0);
    ~PacketFilter();

private:
    Ui::PacketFilter *ui;
};

#endif // PACKETFILTER_H
