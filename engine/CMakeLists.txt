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

target_sources(intriqo_engine_lib
    PRIVATE
        src/common/types.cpp
        src/packet/parser.cpp
        src/flow/flow_table.cpp
        src/features/extractor.cpp
        src/events/security_event.cpp
        src/detection/port_scan_detector.cpp
        src/pipeline/pipeline_impl.cpp
        src/transport/event_sink.cpp
        src/capture/pcap_source.cpp
        src/capture/synthetic_source.cpp
        src/capture/live_source.cpp
        src/detection/detector_registry.cpp
        src/runtime/engine_impl.cpp
)

target_compile_features(intriqo_engine_lib PUBLIC cxx_std_20)
find_package(Threads REQUIRED)
target_link_libraries(intriqo_engine_lib PUBLIC Threads::Threads)

add_executable(intriqo-engine tools/engine_main.cpp)
target_link_libraries(intriqo-engine PRIVATE intriqo_engine_lib)
add_executable(intriqo-runtime-benchmark tools/benchmark_runtime.cpp)
target_link_libraries(intriqo-runtime-benchmark PRIVATE intriqo_engine_lib)

add_executable(intriqo_port_scan_demo tools/port_scan_demo.cpp)
target_link_libraries(intriqo_port_scan_demo PRIVATE intriqo_engine_lib)
target_include_directories(intriqo_port_scan_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_executable(intriqo_engine_benchmark tools/benchmark_pipeline.cpp)
target_link_libraries(intriqo_engine_benchmark PRIVATE intriqo_engine_lib)
target_include_directories(intriqo_engine_benchmark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# =============================================================================
# cmake/ modules (find-packages, helper functions)
# =============================================================================
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# =============================================================================
# Optional: libpcap (live capture and PCAP replay)
# =============================================================================
option(INTRIQO_ENABLE_PCAP "Enable Linux live capture when libpcap is available" ON)
find_package(PkgConfig QUIET)
if(INTRIQO_ENABLE_PCAP AND PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET IMPORTED_TARGET libpcap)
endif()
if(INTRIQO_ENABLE_PCAP AND NOT PCAP_FOUND)
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        set(PCAP_FOUND TRUE)
    endif()
endif()

if(INTRIQO_ENABLE_PCAP AND PCAP_FOUND)
    target_compile_definitions(intriqo_engine_lib PUBLIC INTRIQO_HAS_PCAP)
    if(TARGET PkgConfig::PCAP)
        target_link_libraries(intriqo_engine_lib PRIVATE PkgConfig::PCAP)
    else()
        target_include_directories(intriqo_engine_lib PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(intriqo_engine_lib PRIVATE ${PCAP_LIBRARY})
    endif()
    message(STATUS "Intriqo engine: libpcap found — live capture enabled")
else()
    message(STATUS "Intriqo engine: libpcap disabled/unavailable — offline capture works; live capture reports an error")
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
if(INTRIQO_BUILD_BENCHMARKS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks")
    add_subdirectory(tests/benchmarks)
endif()
