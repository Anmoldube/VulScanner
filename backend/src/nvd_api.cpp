\ 
    #include "nvd_api.h"
    #include <curl/curl.h>
    #include <nlohmann/json.hpp>
    #include <iostream>
    #include <string>

    using json = nlohmann::json;

    static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    std::pair<std::string,std::string> fetch_cve_info_from_nvd(const std::string &cve_id, const std::string &api_key) {
        std::string url = "https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id;
        CURL *curl = curl_easy_init();
        if (!curl) return {"",""};
        std::string readBuffer;
        struct curl_slist *headers = NULL;
        if (!api_key.empty()) {
            std::string h = "apiKey: " + api_key;
            headers = curl_slist_append(headers, h.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        CURLcode res = curl_easy_perform(curl);
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK) return {"",""};
        try {
            auto j = json::parse(readBuffer);
            auto item = j["result"]["CVE_Items"][0];
            std::string desc = item["cve"]["description"]["description_data"][0]["value"].get<std::string>();
            std::string score = "unknown";
            // parse CVSSv3 if present
            if (item.contains("impact") && item["impact"].contains("baseMetricV3")) {
                score = std::to_string(item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"].get<float>());
            }
            return {score, desc};
        } catch (...) {
            return {"",""};
        }
    }
