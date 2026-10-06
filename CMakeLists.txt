cmake_minimum_required(VERSION 3.12)
project(heapcommit)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(${PROJECT_NAME}_lib STATIC
	src/HeapCommit.cpp
)

target_include_directories(${PROJECT_NAME}_lib PUBLIC include)
target_link_libraries(${PROJECT_NAME}_lib PUBLIC ntdll)

add_executable(${PROJECT_NAME}_demo
	src/Main.cpp
)

target_link_libraries(${PROJECT_NAME}_demo PRIVATE ${PROJECT_NAME}_lib)

set_target_properties(${PROJECT_NAME}_demo PROPERTIES
	OUTPUT_NAME ${PROJECT_NAME}
	RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
