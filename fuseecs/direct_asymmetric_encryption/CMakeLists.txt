cmake_minimum_required(VERSION 3.0.2)

add_library(directRsaEncryption SHARED direct_rsa_encryption.c)
add_definitions(-Wall -D_FILE_OFFSET_BITS=64)
target_link_libraries(directRsaEncryption ${GPGME_VANILLA_LIBRARIES} ${LIBGCRYPT_LIBS})
install(TARGETS directRsaEncryption DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})

install(FILES parse_public_key.py DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})