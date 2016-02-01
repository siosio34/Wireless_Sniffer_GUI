#-------------------------------------------------
#
# Project created by QtCreator 2016-01-31T02:51:43
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Wireless_Sniffer_GUI
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    sniffer.cpp \
    deviceselector.cpp

HEADERS  += mainwindow.h \
    sniffer.h \
    deviceselector.h \
    ieee80211_radiotap.h

FORMS    += mainwindow.ui \
    deviceselector.ui

CONFIG += c++11
LIBS += -lpcap

