\ 
    #include <lua.hpp>
    #include <iostream>

    extern "C" int luaopen_vulnscanner(lua_State* L);

    int main(int argc, char** argv) {
        if (argc < 2) {
            std::cerr << "Usage: scanner_runner <script.lua> [args...]\n";
            return 1;
        }
        const char* script = argv[1];

        lua_State* L = luaL_newstate();
        luaL_openlibs(L);

        luaL_requiref(L, "vulnscanner", luaopen_vulnscanner, 1);
        lua_pop(L, 1);

        // push script arguments into global arg table
        lua_newtable(L);
        for (int i = 1; i < argc; ++i) {
            lua_pushinteger(L, i-1);
            lua_pushstring(L, argv[i]);
            lua_settable(L, -3);
        }
        lua_setglobal(L, "arg");

        if (luaL_dofile(L, script) != LUA_OK) {
            std::cerr << "Lua error: " << lua_tostring(L, -1) << std::endl;
            lua_close(L);
            return 1;
        }
        lua_close(L);
        return 0;
    }
