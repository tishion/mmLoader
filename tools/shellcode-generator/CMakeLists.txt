project(mmloader-shellcode-generator)

add_executable(${PROJECT_NAME}
    mmloader-shellcode-generator.c
    ../../src/mmloader/mmloader.h
    ../../src/mmloader/mmloader.c
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Shlwapi
)

target_link_options(${PROJECT_NAME} PRIVATE
    /OPT:NOREF
    /OPT:NOICF
    /INCREMENTAL:NO
    /ORDER:@${CMAKE_CURRENT_SOURCE_DIR}/functionorder
    /SUBSYSTEM:WINDOWS
)

# add post build event to copy the header files
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND $<TARGET_FILE:${PROJECT_NAME}> "${CMAKE_SOURCE_DIR}\\output\\mmloader\\include\\"
)

# install lib and header files
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION tools
)

if (BUILD_ARC_X8632)
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
