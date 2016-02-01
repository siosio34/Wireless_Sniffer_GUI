#include "deviceselector.h"
#include "ui_deviceselector.h"

DeviceSelector::DeviceSelector(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceSelector)
{
    ui->setupUi(this);
    PrintDevList();

}

DeviceSelector::~DeviceSelector()
{
    delete ui;
}

void DeviceSelector::PrintDevList()
{

    pcap_if_t *alldevs; // device list
    pcap_if_t *d; // for_loop_variable

    if (pcap_findalldevs(&alldevs,errbuf) == PCAP_ERROR)
    {
      close();
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        ui->listWidget->addItem(d->name); // add Device List
    }

}


void DeviceSelector::on_SelectDev_clicked(QAbstractButton *button)
{
    QPushButton* OkButton = (QPushButton*)button;
    if(OkButton == ui->SelectDev->button(QDialogButtonBox::Ok))
    {
        QListWidgetItem *item = ui->listWidget->currentItem();
        const char *dev = item->text().toStdString().c_str();
        DeviceHandle = pcap_open_live(dev, 65536, 1, -1, errbuf);

    }

    close();
}
