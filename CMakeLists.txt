cmake_minimum_required(VERSION 3.20)
project(HeapCommit CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
	add_compile_options(/W4 /WX /permissive- /utf-8)
	add_compile_options(/we4242 /we4244 /we4287 /we4355 /we4365 /we4800)
else()
	add_compile_options(-Wall -Wextra -Werror)
	add_compile_options(-Wconversion -Wsign-conversion -Wold-style-cast)
	add_compile_options(-Wswitch-enum -Wshadow -Wnull-dereference)
endif()

add_subdirectory(src)

find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
	add_custom_target(
		format
		COMMAND ${CLANG_FORMAT} -i -style=file
			include/*.hpp
			src/*.cpp src/*.hpp
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)
	add_custom_target(
		format-check
		COMMAND ${CLANG_FORMAT} --dry-run -Werror -style=file
			include/*.hpp
			src/*.cpp src/*.hpp
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)
endif()
