cmake_minimum_required(VERSION 3.0.2)
project(encrypting-cloud-storages)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake-Modules)
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/build)

include(FindPythonModule)
include(GNUInstallDirs)

find_package(Git)
execute_process (COMMAND ${GIT_EXECUTABLE} submodule init)
execute_process (COMMAND ${GIT_EXECUTABLE} submodule update)

find_package(Gpgme REQUIRED)
if(NOT GPGME_FOUND)
	message(FATAL_ERROR "Could not find GPGME")
endif()
find_package(Libgcrypt REQUIRED)
find_package(fuse REQUIRED)

find_program(MAKEPASSWD makepasswd)
if(${MAKEPASSWD} STREQUAL "MAKEPASSWD-NOTFOUND")
	message(FATAL_ERROR "Could not find makepasswd")
endif()

find_package(Threads REQUIRED)
find_package(PythonInterp REQUIRED)

find_python_module(pgpdump REQUIRED)
if(NOT PY_PGPDUMP)
	message(FATAL_ERROR "Could not find python-pgpdump")
endif()

SET(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES} ".so.3")
find_library(OPENSC opensc)
if(${OPENSC} STREQUAL "OPENSC-NOTFOUND")
	message(FATAL_ERROR "Could not find libopensc")
endif()

find_program(AUTOCONF autoconf)
if(${AUTOCONF} STREQUAL "AUTOCONF-NOTFOUND")
	message(FATAL_ERROR "Could not find autoconf")
endif()

add_subdirectory(fuseecs)
add_subdirectory(share_a_folder)