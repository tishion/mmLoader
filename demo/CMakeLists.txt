project(mmloader-demo)

if(BUILD_ARC_X8632)
    set(MMLOADER_DEMO_OUT ${CMAKE_SOURCE_DIR}/output/demo/x86)
elseif(BUILD_ARC_X8664)
    set(MMLOADER_DEMO_OUT ${CMAKE_SOURCE_DIR}/output/demo/x64)
else()
    message(FATAL_ERROR "Unsupported Architecture")
endif()

# ################################################
file(GLOB_RECURSE demo_module_SRC_FILES
    "./demo-module/*.h"
    "./demo-module/*.c"
    "./demo-module/*.cpp"
)
add_library(demo-module SHARED
    ${demo_module_SRC_FILES}
)
target_compile_definitions(demo-module PUBLIC -DDEMOMODULE_EXPORTS)
set_target_properties(demo-module PROPERTIES
    FOLDER demo
    ARCHIVE_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/bin"
    RUNTIME_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/bin"
)

# ################################################
file(GLOB_RECURSE demo_mmloader_SRC_FILES
    "./demo-mmloader/*.h"
    "./demo-mmloader/*.c"
    "./demo-mmloader/*.cpp"
)

add_executable(demo-mmloader
    ${demo_mmloader_SRC_FILES}
)

set_target_properties(demo-mmloader PROPERTIES
    FOLDER demo
    ARCHIVE_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/bin"
    RUNTIME_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/bin"
)

target_link_libraries(demo-mmloader
    PRIVATE
    Shlwapi

    mmloader
)

add_dependencies(demo-mmloader demo-module)

# ################################################
if(BUILD_SHELLCODE_GEN)
    file(GLOB_RECURSE demo_mmloader_shellcode_SRC_FILES
        "./demo-mmloader-shellcode/*.h"
        "./demo-mmloader-shellcode/*.c"
        "./demo-mmloader-shellcode/*.cpp"
    )

    add_executable(demo-mmloader-shellcode
        ${demo_mmloader_shellcode_SRC_FILES}
    )

    target_link_libraries(demo-mmloader-shellcode
        PRIVATE
        Shlwapi
    )

    add_dependencies(demo-mmloader-shellcode
        mmloader-shellcode-generator
    )

    # Include paths
    target_include_directories(demo-mmloader-shellcode
        PRIVATE
        ${CMAKE_SOURCE_DIR}/output/mmloader/include
    )

    set_target_properties(demo-mmloader-shellcode PROPERTIES
        FOLDER demo
        ARCHIVE_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/bin"
        RUNTIME_OUTPUT_DIRECTORY "${MMLOADER_DEMO_OUT}/bin"
    )
endif()
