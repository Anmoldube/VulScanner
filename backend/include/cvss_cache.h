#pragma once
#include <string>

std::string get_cvss_score_cached(const std::string& cve_id);
void save_cvss_to_cache(const std::string& cve_id, const std::string &score);
