\ 
    #include "mainwindow.h"
    #include <QVBoxLayout>
    #include <QHBoxLayout>
    #include <QLineEdit>
    #include <QTextEdit>
    #include <QPushButton>
    #include <QProcess>
    #include <QFileDialog>
    #include <QMessageBox>

    MainWindow::MainWindow(QWidget* parent) : QWidget(parent) {
        auto *layout = new QVBoxLayout(this);
        auto *h = new QHBoxLayout();
        inputHost = new QLineEdit();
        inputHost->setPlaceholderText("Target (e.g., 127.0.0.1)");
        h->addWidget(inputHost);
        startButton = new QPushButton("Run Lua Script");
        h->addWidget(startButton);
        layout->addLayout(h);

        outputBox = new QTextEdit();
        outputBox->setReadOnly(true);
        layout->addWidget(outputBox);

        proc = new QProcess(this);
        connect(startButton, &QPushButton::clicked, this, &MainWindow::startScript);
        connect(proc, &QProcess::readyReadStandardOutput, this, &MainWindow::readStdout);
        connect(proc, &QProcess::readyReadStandardError, this, &MainWindow::readStderr);

        setLayout(layout);
        setWindowTitle("VulnScanner GUI - Lua Runner");
        resize(700,500);
    }

    void MainWindow::startScript() {
        QString host = inputHost->text().trimmed();
        if (host.isEmpty()) host = "127.0.0.1";
        outputBox->clear();
        // assume scanner_runner is in ../backend relative to frontend build/run location
        QString prog = QCoreApplication::applicationDirPath() + "/../backend/scanner_runner";
        QString script = QCoreApplication::applicationDirPath() + "/../scripts/example_scan.lua";
        // allow using bundled binary path fallback
        if (!QFile::exists(prog)) prog = "./scanner_runner";
        if (!QFile::exists(script)) {
            QMessageBox::warning(this, "Script missing", "example_scan.lua not found relative to executable.");
            return;
        }
        proc->start(prog, QStringList{script, host});
        if (!proc->waitForStarted(2000)) {
            QMessageBox::critical(this, "Error", "Failed to start scanner_runner. Make sure it is built and executable.");
        }
    }

    void MainWindow::readStdout() {
        QByteArray out = proc->readAllStandardOutput();
        outputBox->append(QString::fromLocal8Bit(out));
    }

    void MainWindow::readStderr() {
        QByteArray err = proc->readAllStandardError();
        outputBox->append(QString::fromLocal8Bit(err));
    }
