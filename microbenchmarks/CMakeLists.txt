set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/microbenchmarks)

set(mbenchbin "")

macro(add_microbenchmark source_name)
    add_executable(${source_name} ${source_name}.cpp utils.cpp)
    target_link_libraries(${source_name} Threads::Threads NTL GMP Boost::program_options nlohmann_json::nlohmann_json)
    list(APPEND mbenchbin ${source_name})
endmacro()

add_microbenchmark(mult_gf2e)
add_microbenchmark(add_gf2e)
add_microbenchmark(ecc_gf2e)
add_microbenchmark(precon_gf2e)

add_executable(comm_runner comm_runner.cpp utils.cpp)
target_link_libraries(comm_runner Threads::Threads NTL GMP Boost::program_options nlohmann_json::nlohmann_json ConstRoundLPN EMPTool)
list(APPEND mbenchbin comm_runner)

add_custom_target(microbenchmarks)
add_dependencies(microbenchmarks ${mbenchbin})
