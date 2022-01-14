cmake_minimum_required(VERSION 3.0.2)

add_executable(data_operations_test data_operations_test.c)
target_link_libraries(data_operations_test criterion)

add_test(NAME data_operations_test WORKING_DIRECTORY fuseecs/test COMMAND ./data_operations_test)
