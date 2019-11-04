cmake_minimum_required(VERSION 2.6)

set(TARGET "glicHook")

project(${TARGET})

set(DIR_SRC main.cpp)

add_definitions("-Wall -g")

add_executable(${TARGET} ${DIR_SRC})
target_link_libraries(${TARGET} pthread testso)


add_library(testso SHARED 3rdtest.cpp)

