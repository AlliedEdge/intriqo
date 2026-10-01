# =============================================================================
# IntriqoHelpers.cmake
# Reusable CMake helper functions for the Intriqo engine.
# =============================================================================

# intriqo_add_unit_test(TARGET <name> SOURCES <src>... [LIBRARIES <lib>...])
#   Creates a CTest-registered test executable linked against intriqo_engine_lib.
function(intriqo_add_unit_test)
    cmake_parse_arguments(ARG "" "TARGET" "SOURCES;LIBRARIES" ${ARGN})

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "intriqo_add_unit_test: TARGET is required")
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "intriqo_add_unit_test: SOURCES is required")
    endif()

    add_executable(${ARG_TARGET} ${ARG_SOURCES})
    target_link_libraries(${ARG_TARGET}
        PRIVATE
            intriqo_engine_lib
            ${ARG_LIBRARIES}
    )
    target_include_directories(${ARG_TARGET}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/engine/include
    )
    add_test(NAME ${ARG_TARGET} COMMAND ${ARG_TARGET})
    set_tests_properties(${ARG_TARGET} PROPERTIES TIMEOUT 30)
endfunction()
