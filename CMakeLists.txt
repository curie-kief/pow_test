cmake_minimum_required(VERSION 2.6)
project(slow_hash)

find_package( Threads )

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

set(CMAKE_CXX_FLAGS "-O3")
set(CMAKE_C_FLAGS "-O3")

file(GLOB SRCFILES *.cpp pow_hash/*.cpp crypto/*.c)
add_executable(slow_hash "${SRCFILES}")

install(TARGETS slow_hash RUNTIME DESTINATION bin)

target_link_libraries( slow_hash ${CMAKE_THREAD_LIBS_INIT} )
