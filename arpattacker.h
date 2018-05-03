#ifndef ARPATTACKER_H
#define ARPATTACKER_H

#include <QWidget>

namespace Ui {
class ArpAttacker;
}

class ArpAttacker : public QWidget
{
    Q_OBJECT

public:
    explicit ArpAttacker(QWidget *parent = 0);
    ~ArpAttacker();

private:
    Ui::ArpAttacker *ui;
};

#endif // ARPATTACKER_H
