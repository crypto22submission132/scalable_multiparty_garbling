set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests)

add_executable(io_test io.cpp)
target_link_libraries(io_test Boost::unit_test_framework Threads::Threads EMPTool ConstRoundLPN)

add_test(NAME io_test COMMAND io_test)
