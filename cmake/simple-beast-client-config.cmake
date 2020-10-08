include(CMakeFindDependencyMacro)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/modules")

find_dependency(Boost 1.66 REQUIRED COMPONENTS date_time regex system)
find_dependency(OpenSSL REQUIRED)
find_dependency(cppcodec REQUIRED)

include("${CMAKE_CURRENT_LIST_DIR}/simple-beast-client-targets.cmake")
