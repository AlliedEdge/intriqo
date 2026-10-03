cmake_minimum_required(VERSION 3.24)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/IntriqoHelpers.cmake)

# =============================================================================
# Fetch GoogleTest (header-only, no install required)
# =============================================================================
include(FetchContent)
FetchContent_Declare(
    googletest
    URL      https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    URL_HASH SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
)
# Prevent GTest from overriding compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# =============================================================================
# Unit tests
# =============================================================================
add_subdirectory(unit)

# =============================================================================
# Integration tests
# =============================================================================
add_subdirectory(integration)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME RuntimeCLI COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/test_cli.py $<TARGET_FILE:intriqo-engine>)
    set_tests_properties(RuntimeCLI PROPERTIES TIMEOUT 30)
endif()
