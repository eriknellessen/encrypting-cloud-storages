cmake_minimum_required(VERSION 3.0.2)

execute_process(COMMAND ./configuration.sh ${CMAKE_INSTALL_FULL_BINDIR} ${CMAKE_INSTALL_FULL_LIBDIR} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_library(fuseecsl SHARED fusexmp.c gpg_operations.c)
add_definitions(-Wall ${FUSE_DEFINITIONS} -DHAVE_UTIMENSAT -DHAVE_SETXATTR)
target_link_libraries(fuseecsl ${FUSE_LIBRARIES} ${GPGME_VANILLA_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS fuseecsl DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})

add_executable(fuseecs fuseecs.c)
target_link_libraries(fuseecs fuseecsl)
install(TARGETS fuseecs DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

install(PROGRAMS start_fuseecs.sh DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})