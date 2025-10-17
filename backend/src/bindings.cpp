\ 
    #include <lua.hpp>
    #include "scanner.h"
    #include "nvd_api.h"
    #include "cvss_cache.h"
    #include <vector>
    #include <string>

    static int l_scan_tcp(lua_State* L) {
        const char* host = luaL_checkstring(L, 1);
        int start_port = (int)luaL_checkinteger(L, 2);
        int end_port = (int)luaL_checkinteger(L, 3);
        int concurrency = (int)luaL_optinteger(L, 4, 50);
        int timeout_ms = (int)luaL_optinteger(L, 5, 300);

        std::vector<ScanResult> res = async_scan_tcp(host, start_port, end_port, concurrency, timeout_ms);

        lua_newtable(L);
        int idx = 1;
        for (const auto &r : res) {
            lua_newtable(L);
            lua_pushstring(L, "port"); lua_pushinteger(L, r.port); lua_settable(L, -3);
            lua_pushstring(L, "open"); lua_pushboolean(L, r.open); lua_settable(L, -3);
            lua_pushstring(L, "note"); lua_pushstring(L, r.note.c_str()); lua_settable(L, -3);
            lua_rawseti(L, -2, idx++);
        }
        return 1;
    }

    static int l_udp_probe(lua_State* L) {
        const char* host = luaL_checkstring(L, 1);
        int start_port = (int)luaL_checkinteger(L, 2);
        int end_port = (int)luaL_checkinteger(L, 3);

        std::vector<ScanResult> res = udp_probe(host, start_port, end_port);

        lua_newtable(L);
        int idx = 1;
        for (const auto &r : res) {
            lua_newtable(L);
            lua_pushstring(L, "port"); lua_pushinteger(L, r.port); lua_settable(L, -3);
            lua_pushstring(L, "note"); lua_pushstring(L, r.note.c_str()); lua_settable(L, -3);
            lua_rawseti(L, -2, idx++);
        }
        return 1;
    }

    static int l_fetch_cve(lua_State* L) {
        const char* cve = luaL_checkstring(L, 1);
        const char* api_key = luaL_optstring(L, 2, "");
        auto p = fetch_cve_info_from_nvd(cve, api_key);
        lua_newtable(L);
        lua_pushstring(L, "cvss"); lua_pushstring(L, p.first.c_str()); lua_settable(L, -3);
        lua_pushstring(L, "description"); lua_pushstring(L, p.second.c_str()); lua_settable(L, -3);
        return 1;
    }

    static int l_get_cvss_cached(lua_State* L) {
        const char* cve = luaL_checkstring(L, 1);
        std::string s = get_cvss_score_cached(cve);
        lua_pushstring(L, s.c_str());
        return 1;
    }

    static const struct luaL_Reg mylib[] = {
        {"scan_tcp", l_scan_tcp},
        {"udp_probe", l_udp_probe},
        {"fetch_cve", l_fetch_cve},
        {"get_cvss_cached", l_get_cvss_cached},
        {NULL, NULL}
    };

    extern "C" int luaopen_vulnscanner(lua_State* L) {
        luaL_newlib(L, mylib);
        return 1;
    }
