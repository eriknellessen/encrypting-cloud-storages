cmake_minimum_required(VERSION 3.0.2)

execute_process(COMMAND autoreconf --verbose --install WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/OpenSC)
execute_process(COMMAND ./configure WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/OpenSC)

add_library(directAsymmetricDecryptionOnToken SHARED OpenSC/src/tools/util.c access_token.c)
include_directories(OpenSC OpenSC/src/ OpenSC/src/tools/)

add_definitions(-Wall)

#Using -unresolved-symbols=ignore-in-shared-libs for libnpa, because we do not have it (and will not use it)
#See http://stackoverflow.com/questions/11055569/linking-with-dynamic-library-with-dependencies
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -unresolved-symbols=ignore-in-shared-libs" )
target_link_libraries(directAsymmetricDecryptionOnToken ${OPENSC})

add_library(card-openpgp-modified SHARED OpenSC/src/libopensc/asn1.c OpenSC/src/libopensc/sc.c OpenSC/src/libopensc/card.c OpenSC/src/libopensc/card-openpgp.c card-openpgp-modified.c)
target_link_libraries(card-openpgp-modified ${OPENSC})
install(TARGETS card-openpgp-modified DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})