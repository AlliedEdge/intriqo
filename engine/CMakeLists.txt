cmake_minimum_required(VERSION 3.24)

project(
    intriqo_engine
    VERSION     0.1.0
    DESCRIPTION "Intriqo IDS Engine — high-performance packet capture, flow tracking, and detection"
    LANGUAGES   CXX
)

# =============================================================================
# Engine library
# =============================================================================
add_library(intriqo_engine_lib STATIC)

target_include_directories(intriqo_engine_lib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Sources — stub until subsystem implementations are added
target_sources(intriqo_engine_lib
    PRIVATE
        src/engine_stub.cpp
)

target_compile_features(intriqo_engine_lib PUBLIC cxx_std_20)

# =============================================================================
# cmake/ modules (find-packages, helper functions)
# =============================================================================
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# =============================================================================
# Optional: libpcap (live capture and PCAP replay)
# =============================================================================
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET libpcap)
endif()

if(PCAP_FOUND)
    target_compile_definitions(intriqo_engine_lib PUBLIC INTRIQO_HAS_PCAP)
    target_include_directories(intriqo_engine_lib PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(intriqo_engine_lib PRIVATE ${PCAP_LIBRARIES})
    message(STATUS "Intriqo engine: libpcap found — live capture enabled")
else()
    message(STATUS "Intriqo engine: libpcap NOT found — capture stubs will be used")
endif()

# =============================================================================
# Tests
# =============================================================================
if(INTRIQO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# =============================================================================
# Benchmarks
# =============================================================================
if(INTRIQO_BUILD_BENCHMARKS)
    add_subdirectory(tests/benchmarks)
endif()
