#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QObject::connect(&SnifferThread,SIGNAL(started()),&sniffer,SLOT(StartSniffer()));
    QObject::connect(&sniffer,SIGNAL(CapturePacket(ApInfo)),this,SLOT(_CapturePacket(ApInfo)), Qt::BlockingQueuedConnection);
    QObject::connect(&SnifferThread,SIGNAL(finished()),&sniffer,SLOT(StopSniffer()));

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_Push_Sniff_Start_clicked()
{
    DeviceSelector DialDevice;
    DialDevice.show();
    DialDevice.exec();


    if(DialDevice.GetHandle() == NULL)
        QMessageBox::information(NULL,"ERROR", "Device Handle Is Null");

    sniffer.SetHandle(DialDevice.GetHandle());
    sniffer.moveToThread(&SnifferThread);
    SnifferThread.start();

}

void MainWindow::on_Push_Sniff_Stop_clicked()
{
    SnifferThread.quit();
    SnifferThread.wait();
}

void MainWindow::_CapturePacket(ApInfo _apinfo)
{
      QString Bssid;
      Bssid.sprintf("%02X",&(_apinfo._bssid));
      QList<QTreeWidgetItem*> Item = ui->treeWidget->findItems(Bssid, Qt::MatchWildcard, 5);

      if(Bssid == NULL)
          return ;

      if(Item.empty())
      {
         if(_apinfo._ssid != "" && _apinfo._channel != 0 && Bssid != NULL)
         {
             QTreeWidgetItem *ApItem = new QTreeWidgetItem(ui->treeWidget);
             ApItem->setText(0,QString::fromStdString(_apinfo._ssid));
             ApItem->setText(1,QString::number(0));
             ApItem->setText(2,QString::fromStdString(_apinfo._enc));
             ApItem->setText(3,QString::number(_apinfo._channel));
             ApItem->setText(4,QString::number(0));
             ApItem->setText(5,Bssid);

         }
         else
             return ;

      }

      else
      {

      }



}
