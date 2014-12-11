cmake_minimum_required(VERSION 2.8.4)
project(muext)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(SOURCES_DIR ${BASE_DIR}/src)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BASE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${BASE_DIR}/bin)

include_directories(${BASE_DIR}/include)

set(SOURCE_FILES ${SOURCES_DIR}/crypt.cpp ${SOURCES_DIR}/main.cpp)
add_library(muext SHARED ${SOURCE_FILES})
