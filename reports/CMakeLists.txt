cmake_minimum_required(VERSION 3.10)
project(userspace_firewall C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g")

add_executable(msfw main.c)

