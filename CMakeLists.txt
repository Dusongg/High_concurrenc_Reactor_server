cmake_minimum_required(VERSION 3.22.1)
project(RPS)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
FetchContent_Declare(
        glog
        GIT_REPOSITORY https://github.com/google/glog.git
        GIT_TAG v0.7.1
        GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(glog)


add_executable(RPS main.cpp)

target_link_libraries (RPS glog::glog)