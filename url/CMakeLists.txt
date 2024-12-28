cmake_minimum_required(VERSION 3.24)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
project(libmw)

option(LIBMW_BUILD_TESTS "Build libmw tests" OFF)

include(FetchContent)

if(LIBMW_BUILD_TESTS)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
  )
  FetchContent_MakeAvailable(googletest)

  # For unit tests
  FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.18.0
  )
  FetchContent_MakeAvailable(httplib)
endif()

find_package(CURL REQUIRED)

set(SOURCE_FILES
  src/url.cpp
  src/http_client.cpp
)

set(HEADERS
  ../includes/mw/url.hpp
  ../includes/mw/http_client.hpp
)

set(LIBS
  ${CURL_LIBRARIES}
)

set(INCLUDES
  ${CURL_INCLUDE_DIR}
  ../includes/mw
)

add_library(mw-url STATIC ${HEADERS} ${SOURCE_FILES})
# set_target_properties(mw PROPERTIES PUBLIC_HEADER ${HEADERS})
set_property(TARGET mw-url PROPERTY CXX_STANDARD 23)
set_property(TARGET mw-url PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
target_compile_options(mw-url PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(mw-url PRIVATE ${INCLUDES})
target_link_libraries(mw-url PRIVATE ${LIBS})

if(LIBMW_BUILD_TESTS)
  set(TEST_FILES
    src/url_test.cpp
    src/http_client_test.cpp
  )

  # ctest --test-dir build
  add_executable(mw-url_test ${HEADERS} ${SOURCE_FILES} ${TEST_FILES})
  set_property(TARGET mw-url_test PROPERTY CXX_STANDARD 23)
  set_property(TARGET mw-url_test PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
  target_compile_options(mw-url_test PRIVATE -Wall -Wextra -Wpedantic)
  target_include_directories(mw-url_test PRIVATE
    ${INCLUDES}
    ${googletest_SOURCE_DIR}/googletest/include
    ${googletest_SOURCE_DIR}/googlemock/include
  )

  target_link_libraries(mw-url_test PRIVATE
    ${LIBS}
    httplib
    GTest::gtest_main
    GTest::gmock_main
  )

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(mw-url_test
    # Need this so that the unit tests can find the templates.
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
