cmake_minimum_required(VERSION 2.6)

set(TARGET "pltHook")

project(${TARGET})

set(DIR_SRC main.cpp)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")

add_definitions("-Wall -g")

add_executable(${TARGET} ${DIR_SRC})
target_link_libraries(${TARGET} pthread testso)


add_library(testso SHARED testso.cpp)

