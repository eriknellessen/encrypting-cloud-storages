cmake_minimum_required(VERSION 3.0.2)

add_library(showSigner SHARED show_signer_and_get_confirmation.c)
include_directories(${GTK3_INCLUDE_DIRS})
target_link_libraries(showSigner ${GTK3_LIBRARIES} -L/usr/lib/i386-linux-gnu/ -lgio-2.0)
install(TARGETS showSigner DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})