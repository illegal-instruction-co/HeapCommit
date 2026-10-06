add_executable(heapcommit-poc
	main.cpp
	heapcommit.cpp
	heap.cpp
)

target_include_directories(heapcommit-poc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

if(MSVC)
	target_link_libraries(heapcommit-poc PRIVATE ntdll.lib)
else()
	target_link_libraries(heapcommit-poc PRIVATE ntdll)
endif()
