\ 
    #include "pcap_sniffer.h"
    #include <pcap.h>
    #include <thread>
    #include <atomic>
    #include <iostream>

    static std::atomic<bool> running{false};
    static pcap_t *handle = nullptr;

    void start_pcap_sniffer(const std::string &iface, const std::string &filter_expr, std::function<void(const unsigned char*, size_t)> callback) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
            return;
        }
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_expr.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "pcap_compile failed" << std::endl;
            pcap_close(handle);
            handle = nullptr;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "pcap_setfilter failed" << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            handle = nullptr;
            return;
        }
        pcap_freecode(&fp);

        running = true;
        std::thread([callback]() {
            while (running) {
                struct pcap_pkthdr *header;
                const unsigned char *data;
                int res = pcap_next_ex(handle, &header, &data);
                if (res == 1) {
                    callback(data, header->len);
                } else if (res == -1) {
                    std::cerr << "pcap read error" << std::endl;
                    break;
                }
            }
        }).detach();
    }

    void stop_pcap_sniffer() {
        running = false;
        if (handle) {
            pcap_breakloop(handle);
            pcap_close(handle);
            handle = nullptr;
        }
    }
