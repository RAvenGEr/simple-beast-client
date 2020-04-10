cmake_minimum_required (VERSION 3.10)
project (SimpleHttpExample)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.66 REQUIRED COMPONENTS
               date_time regex)
find_package(OpenSSL)
find_package (Threads)
add_definitions(-DENABLE_DIGEST)
add_definitions(-DENABLE_HTTPS)
include_directories( ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../cppcodec
  )
set(SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
  )
add_executable(http-example ${SOURCE} )
IF(WIN32)
  set(EXTRALIBS
      "rpcrt4"
      "crypt32"
      "cryptui")
  if(NOT (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19.0.23026.0))
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
  endif()
ENDIF(WIN32)
target_link_libraries( http-example
    ${OpenCV_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
    ${EXTRALIBS}
    ${CoreFoundation}
    ${IOKit}
  )
