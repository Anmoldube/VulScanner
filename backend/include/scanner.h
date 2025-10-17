#pragma once
#include <string>
#include <vector>

struct ScanResult {
    int port;
    bool open;
    std::string note;
};

std::vector<ScanResult> async_scan_tcp(const std::string &host, int start_port, int end_port, int concurrency, int timeout_ms);
std::vector<ScanResult> udp_probe(const std::string &host, int start_port, int end_port);
bool ping_target(const std::string &host);
