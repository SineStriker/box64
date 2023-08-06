project(bpec LANGUAGES C CXX)

file(GLOB_RECURSE _src *.h *.cpp *.hh *.cc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED on)

add_executable(${PROJECT_NAME} ${_src})