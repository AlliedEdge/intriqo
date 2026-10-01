cmake_minimum_required(VERSION 3.24)

# ── types / common ────────────────────────────────────────────────────────────
add_executable(test_common
    test_types.cpp
)
target_link_libraries(test_common PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_common PRIVATE ${CMAKE_SOURCE_DIR}/engine/include)
gtest_discover_tests(test_common)

# ── packet ────────────────────────────────────────────────────────────────────
add_executable(test_packet
    test_packet.cpp
)
target_link_libraries(test_packet PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_packet PRIVATE ${CMAKE_SOURCE_DIR}/engine/include)
gtest_discover_tests(test_packet)

# ── flow ──────────────────────────────────────────────────────────────────────
add_executable(test_flow
    test_flow.cpp
)
target_link_libraries(test_flow PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_flow PRIVATE ${CMAKE_SOURCE_DIR}/engine/include)
gtest_discover_tests(test_flow)

# ── features ──────────────────────────────────────────────────────────────────
add_executable(test_features
    test_features.cpp
)
target_link_libraries(test_features PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_features PRIVATE ${CMAKE_SOURCE_DIR}/engine/include)
gtest_discover_tests(test_features)

# ── security events ───────────────────────────────────────────────────────────
add_executable(test_events
    test_security_event.cpp
)
target_link_libraries(test_events PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_events PRIVATE ${CMAKE_SOURCE_DIR}/engine/include)
gtest_discover_tests(test_events)
