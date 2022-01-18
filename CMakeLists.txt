cmake_minimum_required(VERSION 3.0.2)
project(encrypting-cloud-storages)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake-Modules)
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/build)

include(FindPythonModule)
include(GNUInstallDirs)

find_package(Git REQUIRED)
execute_process (COMMAND ${GIT_EXECUTABLE} submodule init)
execute_process (COMMAND ${GIT_EXECUTABLE} submodule update)

find_package(Gpgme REQUIRED)
if(NOT GPGME_FOUND)
	message(FATAL_ERROR "Could not find GPGME")
endif()
find_package(Libgcrypt REQUIRED)
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
find_package(PythonInterp REQUIRED)

find_python_module(pgpdump REQUIRED)
if(NOT PY_PGPDUMP)
	message(FATAL_ERROR "Could not find python-pgpdump")
endif()

SET(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES} ".so.3" ".so.4")
find_library(OPENSC opensc)
if(${OPENSC} STREQUAL "OPENSC-NOTFOUND")
	message(FATAL_ERROR "Could not find libopensc")
endif()
message("PLEASE NOTICE, THAT OPENSC MUST BE VERSION 0.16.0~rc2-1.")

find_program(AUTOCONF autoconf)
if(${AUTOCONF} STREQUAL "AUTOCONF-NOTFOUND")
	message(FATAL_ERROR "Could not find autoconf")
endif()

find_program(PCSCD pcscd)
if(${PCSCD} STREQUAL "PCSCD-NOTFOUND")
	message(FATAL_ERROR "Could not find pcscd")
endif()

find_library(ASSUAN_LIBRARY assuan)
if(${ASSUAN_LIBRARY} STREQUAL "ASSUAN_LIBRARY-NOTFOUND")
	message(FATAL_ERROR "Could not find libassuan")
endif()

find_path(ASSUAN_INCLUDE_DIR assuan.h)
if(${ASSUAN_INCLUDE_DIR} STREQUAL "ASSUAN_INCLUDE_DIR-NOTFOUND")
	message(FATAL_ERROR "Could not find libassuan header files")
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
