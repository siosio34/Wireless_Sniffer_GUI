#ifndef DEVICESELECTOR_H
#define DEVICESELECTOR_H

#include <pcap.h>
#include <QDialog>
#include <QAbstractButton>
#include <QMessageBox>


namespace Ui {
class DeviceSelector;
}

class DeviceSelector : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceSelector(QWidget *parent = 0);
    ~DeviceSelector();
    void PrintDevList();
    pcap_t *GetHandle() { return DeviceHandle ;}

private slots:
    void on_SelectDev_clicked(QAbstractButton *button);

private:
    Ui::DeviceSelector *ui;
    pcap_t *DeviceHandle; // device handle
    char errbuf[PCAP_ERRBUF_SIZE];

};

#endif // DEVICESELECTOR_H
