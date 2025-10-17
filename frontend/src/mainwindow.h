#pragma once
#include <QWidget>
#include <QProcess>

class QLineEdit;
class QComboBox;
class QTextEdit;
class QPushButton;

class MainWindow : public QWidget {
    Q_OBJECT
public:
    MainWindow(QWidget* parent=nullptr);

private slots:
    void startScript();
    void readStdout();
    void readStderr();

private:
    QLineEdit *inputHost;
    QTextEdit *outputBox;
    QPushButton *startButton;
    QProcess *proc;
};
