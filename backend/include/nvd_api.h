#pragma once
#include <string>
#include <utility>

// returns pair<score_string, description>
std::pair<std::string,std::string> fetch_cve_info_from_nvd(const std::string &cve_id, const std::string &api_key);
