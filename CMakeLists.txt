cmake_minimum_required(VERSION 3.0.2)
project(encrypting-cloud-storages)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake-Modules)
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/build)

include(GNUInstallDirs)

find_package(Gpgme REQUIRED)
if(NOT GPGME_FOUND)
	message(FATAL_ERROR "Could not find GPGME")
endif()
find_package(fuse REQUIRED)
if(NOT FUSE_FOUND)
	message(FATAL_ERROR "Could not find FUSE")
endif()

find_program(MAKEPASSWD makepasswd)
if(${MAKEPASSWD} STREQUAL "MAKEPASSWD-NOTFOUND")
	message(FATAL_ERROR "Could not find makepasswd")
endif()

find_program(ENCFS encfs)
if(${ENCFS} STREQUAL "ENCFS-NOTFOUND")
	message(FATAL_ERROR "Could not find encfs")
endif()

find_package(Threads REQUIRED)

find_package(GTK3 REQUIRED)
if(NOT GTK3_FOUND)
	message(FATAL_ERROR "Could not find GTK3")
endif()

find_package(CMocka REQUIRED)
if(NOT CMOCKA_FOUND)
	message(FATAL_ERROR "Could not find cmocka")
endif()

enable_testing()
add_compile_options(--coverage)
add_link_options(--coverage)
add_subdirectory(fuseecs)
add_subdirectory(share_a_folder)
