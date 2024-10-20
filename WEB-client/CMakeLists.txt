cmake_minimum_required(VERSION 3.10)

# Project name
project(CrowProject)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories for headers
include_directories(include)

# Find the SQLite3 library
find_package(SQLite3 REQUIRED)

# Add the executable target
add_executable(CrowApp main.cpp)

# Link SQLite3 library
target_link_libraries(CrowApp SQLite::SQLite3)

# For multi-threading support
find_package(Threads REQUIRED)
target_link_libraries(CrowApp Threads::Threads)
