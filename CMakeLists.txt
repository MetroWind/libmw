# cmake -B build . && cmake --build build -j
cmake_minimum_required(VERSION 3.24)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
project(libmw)

option(LIBMW_BUILD_TESTS "Build libmw tests" OFF)

include(FetchContent)

if(LIBMW_BUILD_TESTS)
  message("Will build libmw tests.")
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
else()
  message("Not building libmw tests.")
endif()

find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)

set(SOURCE_FILES
  src/database.cpp
  src/exec.cpp
  src/http_client.cpp
  src/url.cpp
)

set(HEADERS
  includes/mw/database.hpp
  includes/mw/error.hpp
  includes/mw/exec.hpp
  includes/mw/http_client.hpp
  includes/mw/http_client_mock.hpp
  includes/mw/url.hpp
  includes/mw/test_utils.hpp
  includes/mw/utils.hpp
)

set(LIBS
  ${CURL_LIBRARIES}
  ${SQLite3_LIBRARIES}
)

set(INCLUDES
  ${CURL_INCLUDE_DIR}
  ${SQLite3_INCLUDE_DIRS}
  includes/mw
)

add_library(mw STATIC ${HEADERS} ${SOURCE_FILES})
# set_target_properties(mw PROPERTIES PUBLIC_HEADER ${HEADERS})
set_property(TARGET mw PROPERTY CXX_STANDARD 23)
set_property(TARGET mw PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
target_compile_options(mw PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(mw PRIVATE ${INCLUDES})
target_link_libraries(mw PRIVATE ${LIBS})

if(LIBMW_BUILD_TESTS)
  set(TEST_FILES
    src/database_test.cpp
    src/exec_test.cpp
    src/http_client_test.cpp
    src/url_test.cpp
    src/utils_test.cpp
  )

  # ctest --test-dir build
  add_executable(mw_test ${HEADERS} ${SOURCE_FILES} ${TEST_FILES})
  set_property(TARGET mw_test PROPERTY CXX_STANDARD 23)
  set_property(TARGET mw_test PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
  target_compile_options(mw_test PRIVATE -Wall -Wextra -Wpedantic)
  target_include_directories(mw_test PRIVATE
    ${INCLUDES}
    ${googletest_SOURCE_DIR}/googletest/include
    ${googletest_SOURCE_DIR}/googlemock/include
  )

  target_link_libraries(mw_test PRIVATE
    ${LIBS}
    httplib
    GTest::gtest_main
    GTest::gmock_main
  )

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(mw_test
    # Need this so that the unit tests can find the templates.
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
