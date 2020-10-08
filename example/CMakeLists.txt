add_executable(http-example main.cpp)

if(WIN32 AND NOT (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19.0.23026.0))
    target_compile_options(http-example PRIVATE "/bigobj")
endif()

target_link_libraries(http-example PRIVATE
    simple-beast-client::simple-beast-client
)
