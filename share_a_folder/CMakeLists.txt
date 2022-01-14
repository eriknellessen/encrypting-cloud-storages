cmake_minimum_required(VERSION 3.0.2)

add_executable(share_a_folder share_a_folder.c)
add_definitions(-Wall -D_FILE_OFFSET_BITS=64)
target_link_libraries(share_a_folder fuseecsl)
install(TARGETS share_a_folder DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

install(PROGRAMS start_share_a_folder.sh DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
