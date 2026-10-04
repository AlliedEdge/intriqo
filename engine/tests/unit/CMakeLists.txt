cmake_minimum_required(VERSION 3.24)

# ── types / common ────────────────────────────────────────────────────────────
add_executable(test_common
    test_types.cpp
)
target_link_libraries(test_common PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_common PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_common)

# ── packet ────────────────────────────────────────────────────────────────────
add_executable(test_packet
    test_packet.cpp
)
target_link_libraries(test_packet PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_packet PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_packet)

# ── flow ──────────────────────────────────────────────────────────────────────
add_executable(test_flow
    test_flow.cpp
)
target_link_libraries(test_flow PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_flow PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_flow)

# ── features ──────────────────────────────────────────────────────────────────
add_executable(test_features
    test_features.cpp
)
target_link_libraries(test_features PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_features PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_features)

# ── security events ───────────────────────────────────────────────────────────
add_executable(test_events
    test_security_event.cpp
)
target_link_libraries(test_events PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_events PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_events)

add_executable(test_parser test_parser.cpp)
target_link_libraries(test_parser PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_parser PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_parser)

add_executable(test_detection test_detection.cpp)
target_link_libraries(test_detection PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_detection PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_detection)

add_executable(test_syn_flood_detector test_syn_flood_detector.cpp)
target_link_libraries(test_syn_flood_detector PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_syn_flood_detector PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_syn_flood_detector)

add_executable(test_transport test_transport.cpp)
target_link_libraries(test_transport PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_transport PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_transport)
