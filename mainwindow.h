#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <HPcap.h>
#include <CapThread.h>
#include <PacketTableItem.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_startCapButton_clicked();

    void on_finishCapButton_clicked();

    void recMsgfromCap(PacketTableItem);

    void on_packetTable_cellClicked(int row, int column);

    void on_packetTable_cellDoubleClicked(int row, int column);

private:
    Ui::MainWindow *ui;
    CapThread *ct;

signals:
    void sendAdapterIndex(int);

};
#endif // MAINWINDOW_H
