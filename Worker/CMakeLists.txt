cmake_minimum_required(VERSION 3.10)

# Project name
project(Worker)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories for headers
include_directories(include)

# Find the SQLite3 library
find_package(SQLite3 REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread log log_setup)

# Add the executable target
add_executable(Workerapp main.cpp)

# Link SQLite3 library
target_link_libraries(Workerapp SQLite::SQLite3
Boost::system
Boost::thread
Boost::log
Boost::log_setup)


# For multi-threading support
find_package(Threads REQUIRED)
target_link_libraries(Workerapp Threads::Threads)