project(bpec LANGUAGES CXX)

file(GLOB_RECURSE _src *.h *.cpp *.hh *.cc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED on)

# remove_definitions(-std=gnu11)

find_package(capstone REQUIRED)

add_executable(${PROJECT_NAME} ${_src})

target_include_directories(${PROJECT_NAME} PRIVATE ../emu ../include)

target_link_libraries(${PROJECT_NAME} PRIVATE capstone::capstone)