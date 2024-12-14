cmake_minimum_required(VERSION 3.24)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
project(libmw)

include(FetchContent)

find_package(SQLite3 REQUIRED)

set(SOURCE_FILES
  src/database.cpp
)

set(HEADERS
  ../includes/mw/database.hpp
)

set(LIBS
  ${SQLite3_LIBRARIES}
)

set(INCLUDES
  ${CURL_INCLUDE_DIR}
  ../includes/mw
)

add_library(mw-sqlite STATIC ${HEADERS} ${SOURCE_FILES})
set_property(TARGET mw-sqlite PROPERTY CXX_STANDARD 23)
set_property(TARGET mw-sqlite PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
target_compile_options(mw-sqlite PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(mw-sqlite PRIVATE ${INCLUDES})
target_link_libraries(mw-sqlite PRIVATE ${LIBS})

if(LIBMW_BUILD_TESTS)
  set(TEST_FILES
    src/database_test.cpp
  )

  # ctest --test-dir build
  add_executable(mw-sqlite_test ${HEADERS} ${SOURCE_FILES} ${TEST_FILES})
  set_property(TARGET mw-sqlite_test PROPERTY CXX_STANDARD 23)
  set_property(TARGET mw-sqlite_test PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
  target_compile_options(mw-sqlite_test PRIVATE -Wall -Wextra -Wpedantic)
  target_include_directories(mw-sqlite_test PRIVATE
    ${INCLUDES}
    ${googletest_SOURCE_DIR}/googletest/include
    ${googletest_SOURCE_DIR}/googlemock/include
  )

  target_link_libraries(mw-sqlite_test PRIVATE
    ${LIBS}
    httplib
    GTest::gtest_main
    GTest::gmock_main
  )

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(mw-sqlite_test
    # Need this so that the unit tests can find the templates.
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
