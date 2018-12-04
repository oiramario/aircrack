cmake_minimum_required(VERSION 3.0.0)
project(aircrack VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(aircrack main.cpp)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

find_package(Threads)
target_link_libraries (${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})

add_definitions(-D_DEBUG)