cmake_minimum_required(VERSION 3.10)
project(vulnscanner_backend CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system thread)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LUA REQUIRED lua5.3 lua)
find_package(CURL REQUIRED)

include_directories(${Boost_INCLUDE_DIRS} ${LUA_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(scanner_lib STATIC
    src/scanner_async.cpp
    src/pcap_sniffer.cpp
    src/nvd_api.cpp
    src/cvss_cache.cpp
    src/bindings.cpp
)

target_link_libraries(scanner_lib PRIVATE ${Boost_LIBRARIES} ${LUA_LIBRARIES} ${CURL_LIBRARIES} ${PC_LIBPCAP_LIBRARIES})

add_executable(scanner_runner src/main.cpp)
target_link_libraries(scanner_runner PRIVATE scanner_lib ${LUA_LIBRARIES} ${Boost_LIBRARIES} ${CURL_LIBRARIES})

install(TARGETS scanner_runner scanner_lib DESTINATION bin)
