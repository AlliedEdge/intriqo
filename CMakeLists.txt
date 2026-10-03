cmake_minimum_required(VERSION 3.24)

project(
    intriqo
    VERSION      0.1.0
    DESCRIPTION  "Intriqo — Autonomous Multi-Agent Security Operations Centre"
    LANGUAGES    CXX
)

# =============================================================================
# Global C++ standard
# =============================================================================
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# Export compile commands for clangd / IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# =============================================================================
# Build options
# =============================================================================
option(INTRIQO_BUILD_TESTS      "Build test suites"             ON)
option(INTRIQO_BUILD_BENCHMARKS "Build benchmark binaries"      OFF)
option(INTRIQO_ENABLE_ASAN      "Enable AddressSanitizer"       OFF)
option(INTRIQO_ENABLE_TSAN      "Enable ThreadSanitizer"        OFF)

# =============================================================================
# Sanitizer flags (development only; never enable both simultaneously)
# =============================================================================
if(INTRIQO_ENABLE_ASAN AND INTRIQO_ENABLE_TSAN)
    message(FATAL_ERROR "ASAN and TSAN cannot be enabled at the same time.")
endif()

if(INTRIQO_ENABLE_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "Intriqo: AddressSanitizer + UBSan enabled")
endif()

if(INTRIQO_ENABLE_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
    message(STATUS "Intriqo: ThreadSanitizer enabled")
endif()

# =============================================================================
# Compiler warnings
# =============================================================================
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wconversion -Wshadow -Wnull-dereference
        -Wno-unused-parameter
    )
elseif(MSVC)
    add_compile_options(/W4 /permissive-)
endif()

# =============================================================================
# Subdirectories
# =============================================================================
add_subdirectory(engine)
if(INTRIQO_BUILD_TESTS)
    enable_testing()
endif()

# =============================================================================
# Summary
# =============================================================================
message(STATUS "")
message(STATUS "Intriqo ${PROJECT_VERSION}")
message(STATUS "  C++ standard  : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build type    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Tests         : ${INTRIQO_BUILD_TESTS}")
message(STATUS "  Benchmarks    : ${INTRIQO_BUILD_BENCHMARKS}")
message(STATUS "  ASAN          : ${INTRIQO_ENABLE_ASAN}")
message(STATUS "  TSAN          : ${INTRIQO_ENABLE_TSAN}")
message(STATUS "")
