cmake_minimum_required(VERSION 3.24)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
project(libmw)

include(FetchContent)

find_package(OpenSSL REQUIRED)

set(SOURCE_FILES
  src/crypto.cpp
)

set(HEADERS
  ../includes/mw/crypto.hpp
)

set(LIBS
  OpenSSL::Crypto
)

set(INCLUDES
  ../includes/mw
)

add_library(mw-crypto STATIC ${HEADERS} ${SOURCE_FILES})
set_property(TARGET mw-crypto PROPERTY CXX_STANDARD 23)
set_property(TARGET mw-crypto PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
target_compile_options(mw-crypto PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(mw-crypto PRIVATE ${INCLUDES})
target_link_libraries(mw-crypto PRIVATE ${LIBS})

if(LIBMW_BUILD_TESTS)
  set(TEST_FILES
    src/crypto_test.cpp
    ../includes/mw/crypto_mock.hpp
  )

  # ctest --test-dir build
  add_executable(mw-crypto_test ${HEADERS} ${SOURCE_FILES} ${TEST_FILES})
  set_property(TARGET mw-crypto_test PROPERTY CXX_STANDARD 23)
  set_property(TARGET mw-crypto_test PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
  target_compile_options(mw-crypto_test PRIVATE -Wall -Wextra -Wpedantic)
  target_include_directories(mw-crypto_test PRIVATE
    ${INCLUDES}
    ${googletest_SOURCE_DIR}/googletest/include
    ${googletest_SOURCE_DIR}/googlemock/include
  )

  target_link_libraries(mw-crypto_test PRIVATE
    ${LIBS}
    httplib
    GTest::gtest_main
    GTest::gmock_main
  )

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(mw-crypto_test
    # Need this so that the unit tests can find the templates.
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
