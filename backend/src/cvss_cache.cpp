\ 
    #include "cvss_cache.h"
    #include <nlohmann/json.hpp>
    #include <fstream>
    using json = nlohmann::json;

    std::string get_cvss_score_cached(const std::string& cve_id) {
        std::ifstream f("data/cvss_cache.json");
        json cache;
        if (f.good()) { f >> cache; f.close(); }
        if (cache.contains(cve_id)) return cache[cve_id].get<std::string>();
        return "unknown";
    }

    void save_cvss_to_cache(const std::string& cve_id, const std::string &score) {
        std::ifstream f("data/cvss_cache.json");
        json cache;
        if (f.good()) { f >> cache; f.close(); }
        cache[cve_id] = score;
        std::ofstream out("data/cvss_cache.json");
        out << cache.dump(4);
        out.close();
    }
