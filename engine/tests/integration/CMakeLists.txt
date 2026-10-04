cmake_minimum_required(VERSION 3.24)

# Integration tests exercise multiple subsystems end-to-end.
# They are added here as implementations become available.

# Example (uncomment when pipeline implementation exists):
# add_executable(test_pipeline_integration test_pipeline_e2e.cpp)
# target_link_libraries(test_pipeline_integration PRIVATE intriqo_engine_lib GTest::gtest_main)
# gtest_discover_tests(test_pipeline_integration)

message(STATUS "Engine integration tests: pipeline and runtime")
add_executable(test_pipeline test_pipeline.cpp)
target_link_libraries(test_pipeline PRIVATE intriqo_engine_lib GTest::gtest_main)
target_include_directories(test_pipeline PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(test_pipeline)

add_executable(test_runtime test_runtime.cpp)
target_link_libraries(test_runtime PRIVATE intriqo_engine_lib GTest::gtest_main)
gtest_discover_tests(test_runtime)

add_executable(test_capture test_capture.cpp)
target_link_libraries(test_capture PRIVATE intriqo_engine_lib GTest::gtest_main)
gtest_discover_tests(test_capture)

add_executable(test_hardening test_hardening.cpp)
target_link_libraries(test_hardening PRIVATE intriqo_engine_lib GTest::gtest_main)
gtest_discover_tests(test_hardening)

add_executable(test_queued_delivery test_queued_delivery.cpp)
target_link_libraries(test_queued_delivery PRIVATE intriqo_engine_lib GTest::gtest_main)
gtest_discover_tests(test_queued_delivery)
