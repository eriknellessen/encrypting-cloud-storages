cmake_minimum_required(VERSION 3.0.2)

add_executable(data_operations_test data_operations_test.c)
target_link_libraries(data_operations_test cmocka)

add_test(NAME data_operations_test WORKING_DIRECTORY fuseecs/test COMMAND ./data_operations_test)

add_executable(gpg_operations_test ../gpg_operations.c gpg_operations_test.c)
set_target_properties(gpg_operations_test
        PROPERTIES
        LINK_FLAGS  "-g -Wl,--wrap=access"
)
target_link_libraries(gpg_operations_test cmocka ${GPGME_VANILLA_LIBRARIES} directRsaEncryption)

add_test(NAME gpg_operations_test WORKING_DIRECTORY fuseecs/test COMMAND ./gpg_operations_test)
