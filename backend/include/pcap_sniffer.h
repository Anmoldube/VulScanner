#pragma once
#include <functional>
#include <string>

void start_pcap_sniffer(const std::string &iface, const std::string &filter_expr, std::function<void(const unsigned char*, size_t)> callback);
void stop_pcap_sniffer();
