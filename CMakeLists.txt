cmake_minimum_required(VERSION 3.14)
project(simple-beast-client VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SIMPLE_BEAST_CLIENT_BUILD_EXAMPLES "Build the examples as part of the build" ON)
option(SIMPLE_BEAST_CLIENT_ENABLE_HTTPS "Enable HTTPS protocol support" ON)
option(SIMPLE_BEAST_CLIENT_ENABLE_DIGEST "Enable digest authentication support" ON)

# This is needed until cppcodec supports CMake
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.66 REQUIRED COMPONENTS date_time regex system)
find_package(OpenSSL REQUIRED)
find_package(cppcodec REQUIRED)
find_package(Threads REQUIRED)

add_library(simple-beast-client INTERFACE)
add_library(simple-beast-client::simple-beast-client ALIAS simple-beast-client)

target_compile_features(simple-beast-client INTERFACE cxx_std_14)
target_link_libraries(simple-beast-client INTERFACE
    Boost::date_time Boost::regex Boost::system OpenSSL::SSL OpenSSL::Crypto cppcodec::cppcodec Threads::Threads
    $<$<PLATFORM_ID:Windows>:rpcrt4 crypt32 cryptui>
)

target_include_directories(simple-beast-client INTERFACE
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(SIMPLE_BEAST_CLIENT_ENABLE_DIGEST)
    target_compile_definitions(simple-beast-client INTERFACE
        SIMPLE_BEAST_CLIENT_ENABLE_DIGEST
    )
endif()

if(SIMPLE_BEAST_CLIENT_ENABLE_HTTPS)
    target_compile_definitions(simple-beast-client INTERFACE
        SIMPLE_BEAST_CLIENT_ENABLE_HTTPS
    )
endif()

if(SIMPLE_BEAST_CLIENT_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/simple-beast-client-config-version.cmake"
    VERSION ${CMAKE_PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion ARCH_INDEPENDENT
)

install(
    DIRECTORY include/simple-beast-client
    DESTINATION include FILES_MATCHING PATTERN "*.hpp"
)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/Findcppcodec.cmake" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/modules")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/cmake/simple-beast-client-config.cmake" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/cmake/public_modules/Findcppcodec.cmake" DESTINATION share/cmake/simple-beast-client/modules)
install(TARGETS simple-beast-client EXPORT simple-beast-client-targets)
install(
    FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/simple-beast-client-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/simple-beast-client-config-version.cmake"
    DESTINATION share/cmake/simple-beast-client
)
install(EXPORT simple-beast-client-targets
    FILE simple-beast-client-targets.cmake
    NAMESPACE simple-beast-client::
    DESTINATION share/cmake/simple-beast-client
)
export(
    EXPORT simple-beast-client-targets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/simple-beast-client-targets.cmake"
    NAMESPACE simple-beast-client::
)
