add_library(ConstRoundLPN
    io/netmp.cpp)
target_include_directories(ConstRoundLPN PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ConstRoundLPN PUBLIC Boost::system EMPTool)
