cmake_minimum_required(VERSION 3.24)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
project(libmw)

option(LIBMW_BUILD_TESTS "Build libmw tests" OFF)

include(FetchContent)

FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.18.0
)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.12.0
)

FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  # TODO: Use 3.12.1.
  #
  # Temporarily swtich to develop because of
  # https://github.com/nlohmann/json/issues/4756.
  GIT_TAG develop
)

set(SPDLOG_USE_STD_FORMAT ON)
FetchContent_MakeAvailable(httplib spdlog json)

if(LIBMW_BUILD_TESTS)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
  )
  FetchContent_MakeAvailable(googletest)
endif()

set(SOURCE_FILES
  auth.cpp
  http_server.cpp
)

set(HEADERS
  ../includes/mw/auth.hpp
  ../includes/mw/http_server.hpp
)

set(LIBS
  httplib
  spdlog::spdlog
  mw-url
)

set(INCLUDES
  ../includes
  ${httplib_SOURCE_DIR}
  ${json_SOURCE_DIR}/single_include
)

add_library(mw-http-server STATIC ${HEADERS} ${SOURCE_FILES})
# set_target_properties(mw PROPERTIES PUBLIC_HEADER ${HEADERS})
set_property(TARGET mw-http-server PROPERTY CXX_STANDARD 23)
set_property(TARGET mw-http-server PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
target_compile_options(mw-http-server PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(mw-http-server PUBLIC ${INCLUDES})
target_link_libraries(mw-http-server PRIVATE ${LIBS})

if(LIBMW_BUILD_TESTS)
  set(TEST_FILES
    auth_test.cpp
    http_server_test.cpp
  )

  # ctest --test-dir build
  add_executable(mw-http-server_test ${HEADERS} ${SOURCE_FILES} ${TEST_FILES})
  set_property(TARGET mw-http-server_test PROPERTY CXX_STANDARD 23)
  set_property(TARGET mw-http-server_test PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
  target_compile_options(mw-http-server_test PRIVATE -Wall -Wextra -Wpedantic)
  target_include_directories(mw-http-server_test PRIVATE
    ${INCLUDES}
    ${googletest_SOURCE_DIR}/googletest/include
    ${googletest_SOURCE_DIR}/googlemock/include
  )

  target_link_libraries(mw-http-server_test PRIVATE
    ${LIBS}
    GTest::gtest_main
    GTest::gmock_main
  )

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(mw-http-server_test
    # Need this so that the unit tests can find the templates.
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
