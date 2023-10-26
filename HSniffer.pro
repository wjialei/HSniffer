QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    CapThread.cpp \
    HPcap.cpp \
    PacketTableItem.cpp \
    control.cpp \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    CapThread.h \
    HPcap.h \
    PacketTableItem.h \
    control.h \
    mainwindow.h

FORMS += \
    mainwindow.ui

INCLUDEPATH += \
    $$PWD/Include \
    $$PWD/Include/pcap

LIBS += \
    $$PWD/Lib/x64/Packet.lib \
    $$PWD/Lib/x64/wpcap.lib \
    $$PWD/Lib/Packet.lib \
    $$PWD/Lib/wpcap.lib

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
