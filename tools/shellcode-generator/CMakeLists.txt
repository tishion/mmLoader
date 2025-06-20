project(mmloader-shellcode-generator)

add_executable(${PROJECT_NAME}
    mmloader-shellcode-generator.c
    ../../src/mmloader/mmloader.h
    ../../src/mmloader/mmloader.c
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Shlwapi
)

# remove /RTC* from compile flags
foreach(flag_var
    CMAKE_CXX_FLAGS
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_C_FLAGS
    CMAKE_C_FLAGS_DEBUG
    CMAKE_C_FLAGS_RELEASE
)
    STRING(REGEX REPLACE "/RTC[^ ]*" "" ${flag_var} "${${flag_var}}")
endforeach(flag_var)

# compiler options
target_compile_options(${PROJECT_NAME} PRIVATE
    /W3
    /Zi
    /Gy

    # !important!
    # disable security check
    # https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check?view=msvc-170
    /GS-

    # !important!
    # disable code generation optimization
    # https://learn.microsoft.com/en-us/cpp/build/reference/od-disable-debug?view=msvc-170
    /Od
)

# linker options
target_link_options(${PROJECT_NAME} PRIVATE
    /OPT:NOREF
    /OPT:NOICF
    /INCREMENTAL:NO
    /SUBSYSTEM:WINDOWS

    # !important!
    # https://learn.microsoft.com/en-us/cpp/build/reference/order-put-functions-in-order?view=msvc-170
    /ORDER:@${CMAKE_CURRENT_SOURCE_DIR}/functionorder
)

add_dependencies(${PROJECT_NAME} demo-mmloader)

# add post build event to copy the header files
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND $<TARGET_FILE:${PROJECT_NAME}> "${CMAKE_SOURCE_DIR}\\output\\mmloader\\include\\"
)

# install lib and header files
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION tools
)

if(BUILD_ARC_X8632)
    install(FILES ${CMAKE_SOURCE_DIR}/output/mmloader/include/mmLoaderShellCode-x86-Debug.h
        DESTINATION include/mmloader CONFIGURATIONS Debug)
    install(FILES ${CMAKE_SOURCE_DIR}/output/mmloader/include/mmLoaderShellCode-x86-Release.h
        DESTINATION include/mmloader CONFIGURATIONS Release)
elseif(BUILD_ARC_X8664)
    install(FILES ${CMAKE_SOURCE_DIR}/output/mmloader/include/mmLoaderShellCode-x64-Debug.h
        DESTINATION include/mmloader CONFIGURATIONS Debug)
    install(FILES ${CMAKE_SOURCE_DIR}/output/mmloader/include/mmLoaderShellCode-x64-Release.h
        DESTINATION include/mmloader CONFIGURATIONS Release)
else()
    message(FATAL_ERROR "Unsupported Architecture")
endif()
