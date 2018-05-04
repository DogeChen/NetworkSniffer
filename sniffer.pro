#-------------------------------------------------
#
# Project created by QtCreator 2018-04-22T16:03:20
#
#-------------------------------------------------

QT       += core gui

#CONFIG += console
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer
TEMPLATE = app
INCLUDEPATH +=  ".\\Include"
INCLUDEPATH += ".\\Include\\pcap"

LIBS +=  -L"C:\\Users\\Silver\\Documents\\sniffer\\Lib" -lPacket -lwpcap
LIBS += -lws2_32


# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS \
WPCAP \
HAVE_REMOTE\

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    deviceselector.cpp \
    packetfilter.cpp \
    packetcapture.cpp \
    packet.cpp \
    packettree.cpp \
    packettable.cpp \
    packetdex.cpp \
    arpattacker.cpp \
    arppacket.cpp

HEADERS += \
        mainwindow.h \
    deviceselector.h \
    public_header.h \
    packetfilter.h \
    packetcapture.h \
    packet.h \
    packettree.h \
    packettable.h \
    public_qt_header.h \
    packetdex.h \
    arpattacker.h \
    arppacket.h

FORMS += \
        mainwindow.ui \
    deviceselector.ui \
    packetfilter.ui \
    arpattacker.ui
