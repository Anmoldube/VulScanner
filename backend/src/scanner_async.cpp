\ 
    #include "scanner.h"
    #include <boost/asio.hpp>
    #include <boost/asio/steady_timer.hpp>
    #include <thread>
    #include <mutex>
    #include <atomic>
    #include <chrono>
    #include <iostream>
    #include <algorithm>

    using boost::asio::ip::tcp;

    static std::string resolve_host(boost::asio::io_context &ioc, const std::string &host) {
        try {
            tcp::resolver resolver(ioc);
            auto results = resolver.resolve(host, "");
            return results.begin()->endpoint().address().to_string();
        } catch (...) {
            return host;
        }
    }

    std::vector<ScanResult> async_scan_tcp(const std::string &host, int start_port, int end_port, int concurrency, int timeout_ms) {
        boost::asio::io_context ioc;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work = boost::asio::make_work_guard(ioc);

        std::vector<std::thread> threads;
        for (int i = 0; i < concurrency; ++i) {
            threads.emplace_back([&ioc]() { ioc.run(); });
        }

        std::mutex results_mtx;
        std::vector<ScanResult> results;
        std::atomic<int> pending{0};

        std::string target_ip = resolve_host(ioc, host);

        for (int port = start_port; port <= end_port; ++port) {
            pending.fetch_add(1);
            boost::asio::post(ioc, [&, port]() {
                try {
                    auto socket = std::make_shared<tcp::socket>(ioc);
                    tcp::endpoint ep(boost::asio::ip::make_address(target_ip), static_cast<unsigned short>(port));

                    auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

                    // set timer
                    timer->expires_after(std::chrono::milliseconds(timeout_ms));
                    timer->async_wait([socket](const boost::system::error_code &ec) {
                        if (ec) return; // cancelled
                        if (socket->is_open()) {
                            boost::system::error_code ignored;
                            socket->close(ignored);
                        }
                    });

                    socket->async_connect(ep, [socket, port, &results_mtx, &results, timer](const boost::system::error_code &ec) {
                        ScanResult r; r.port = port;
                        if (!ec) {
                            r.open = true; r.note = "Connected";
                            boost::system::error_code ignored;
                            socket->close(ignored);
                        } else {
                            r.open = false; r.note = ec.message();
                        }
                        {
                            std::lock_guard<std::mutex> lg(results_mtx);
                            results.push_back(std::move(r));
                        }
                        // cancel timer
                        boost::system::error_code ignored;
                        timer->cancel(ignored);
                    });
                } catch (std::exception &e) {
                    ScanResult r; r.port = port; r.open = false; r.note = e.what();
                    std::lock_guard<std::mutex> lg(results_mtx);
                    results.push_back(std::move(r));
                }
                pending.fetch_sub(1);
            });
        }

        // wait until posted jobs processed
        while (pending.load() > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        // allow handlers to finish
        work.reset();
        ioc.stop();
        for (auto &t : threads) if (t.joinable()) t.join();

        std::sort(results.begin(), results.end(), [](const ScanResult&a, const ScanResult&b){ return a.port < b.port; });
        return results;
    }

    std::vector<ScanResult> udp_probe(const std::string &host, int start_port, int end_port) {
        std::vector<ScanResult> out;
        try {
            boost::asio::io_context ctx;
            boost::asio::ip::udp::resolver resolver(ctx);
            auto endpoints = resolver.resolve(host, "");
            boost::asio::ip::udp::endpoint ep = *endpoints.begin();

            boost::asio::ip::udp::socket sock(ctx);
            sock.open(boost::asio::ip::udp::v4());
            const char *payload = "vulnprobe";

            for (int port = start_port; port <= end_port; ++port) {
                ScanResult r; r.port = port; r.open = false; r.note = "probe_sent";
                boost::asio::ip::udp::endpoint target_ep(ep.address(), static_cast<unsigned short>(port));
                boost::system::error_code ec;
                sock.send_to(boost::asio::buffer(payload, strlen(payload)), target_ep, 0, ec);
                if (ec) r.note = ec.message();
                out.push_back(r);
                std::this_thread::sleep_for(std::chrono::milliseconds(5)); // rate control
            }
            sock.close();
        } catch (std::exception &e) {
            // return what we have
        }
        return out;
    }

    bool ping_target(const std::string &host) {
    #ifdef _WIN32
        std::string cmd = "ping -n 1 -w 1000 " + host + " > nul";
    #else
        std::string cmd = "ping -c 1 -W 1 " + host + " > /dev/null 2>&1";
    #endif
        int rc = system(cmd.c_str());
        return rc == 0;
    }
