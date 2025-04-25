cmake_minimum_required(VERSION 3.7)

project(idapatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
find_package(IdaSdk REQUIRED)

set(src
    "module.h"
    "module.cpp"
    "patternfind.cpp"
    "patternfind.h"
    "plugin_entry.cpp"
    "Utf8Ini.h")

add_ida_plugin(idapatch plugin_entry.cpp)

set_ida_target_properties(idapatch PROPERTIES CXX_STANDARD 17)
ida_target_include_directories(idapatch PRIVATE ${IdaSdk_INCLUDE_DIRS})

add_ida_library(idapatchlib ${src})
ida_target_link_libraries(idapatch idapatchlib)
