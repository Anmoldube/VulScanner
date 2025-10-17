cmake_minimum_required(VERSION 3.10)
project(vulnscanner_frontend CXX)

set(CMAKE_CXX_STANDARD 17)
find_package(Qt5 COMPONENTS Widgets REQUIRED)

add_executable(vuln_gui
    src/main.cpp
    src/mainwindow.cpp
)
target_include_directories(vuln_gui PRIVATE ${CMAKE_SOURCE_DIR}/backend/include)
target_link_libraries(vuln_gui PRIVATE Qt5::Widgets)
cmake_minimum_required(VERSION 3.16)
project(VulnScanner LANGUAGES C CXX)

# --- Use C++17 standard ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

cmake_minimum_required(VERSION 3.16)
project(VulnScanner LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Lua configuration ---
set(LUA_INCLUDE_DIR "C:/Lua/include")
set(LUA_LIBRARIES "C:/Lua/lib/lua54.lib")

include_directories(${LUA_INCLUDE_DIR})
link_directories("C:/Lua/lib")

add_executable(scanner_runner
    backend/src/main.cpp
    backend/src/ScanController.cpp
    backend/src/Config/config_loader.c
)

target_link_libraries(scanner_runner ${LUA_LIBRARIES})
