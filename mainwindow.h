#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "deviceselector.h"
#include <sniffer.h>\

#include <QMainWindow>
#include <QThread>

#include <string>
#include <string.h>
#include <QList>
#include <QTreeWidgetItem>
#include <QString>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_Push_Sniff_Start_clicked();
    void on_Push_Sniff_Stop_clicked();

    void _CapturePacket(struct ApInfo _apinfo);
    void _PlusPacketNUm(){};




private:
    Ui::MainWindow *ui;
    Sniffer sniffer;
    QThread SnifferThread;



};

#endif // MAINWINDOW_H
