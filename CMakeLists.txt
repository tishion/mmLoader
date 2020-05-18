cmake_minimum_required(VERSION 3.10)
project(mmloader)
message(STATUS "++++++++++ Current build target system:" ${CMAKE_SYSTEM_NAME})

# Determin build platform
message(STATUS "CMAKE_SYSTEM_NAME=" ${CMAKE_SYSTEM_NAME})
string(COMPARE EQUAL "${CMAKE_SYSTEM_NAME}" Windows BUILD_PLATFORM_WINDOWS)

# Determin build arc
message(STATUS "CMAKE_VS_PLATFORM_NAME=" ${CMAKE_VS_PLATFORM_NAME})

# Determin build platform
if ((NOT DEFINED CMAKE_VS_PLATFORM_NAME) OR (CMAKE_VS_PLATFORM_NAME STREQUAL ""))
    message(STATUS "CMAKE_VS_PLATFORM_NAME is empty, use default: Win32")
    set(CMAKE_VS_PLATFORM_NAME Win32)
endif()
message(STATUS "CMAKE_VS_PLATFORM_NAME=" ${CMAKE_VS_PLATFORM_NAME})
string(COMPARE EQUAL "${CMAKE_VS_PLATFORM_NAME}" Win32 BUILD_ARC_X8632)
string(COMPARE EQUAL "${CMAKE_VS_PLATFORM_NAME}" x64 BUILD_ARC_X8664)

# Determin build type
if ((NOT DEFINED CMAKE_BUILD_TYPE) OR (CMAKE_BUILD_TYPE STREQUAL ""))
    message(STATUS "CMAKE_BUILD_TYPE is empty, use default: Debug")
    set(CMAKE_BUILD_TYPE Debug)
endif()
message(STATUS "CMAKE_BUILD_TYPE=" ${CMAKE_BUILD_TYPE})
string(COMPARE EQUAL "${CMAKE_BUILD_TYPE}" Debug BUILD_TYPE_DEBUG)
string(COMPARE EQUAL "${CMAKE_BUILD_TYPE}" Release BUILD_TYPE_RELEASE)

# Validate the build configuration 
if ((NOT BUILD_PLATFORM_WINDOWS) 
    OR ((NOT BUILD_ARC_X8632) AND (NOT BUILD_ARC_X8664)) 
    OR ((NOT BUILD_TYPE_DEBUG) AND (NOT BUILD_TYPE_RELEASE)))
    message(FATAL_ERROR "mmloader supportes only Windows (X86/AMD64) platform.")
endif()

# Flags
# C standard
set(CMAKE_C_STANDARD_REQUIRED ON) 
set(CMAKE_C_STANDARD 11)

# C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

# Build type
set(CMAKE_CONFIGURATION_TYPES Debug Release)

# Default compile flags
set(CMAKE_CXX_FLAGS 
    "/DWIN32 /D_WINDOWS /W3 /WX /GR /GS- /Gy /FAcs /Z7 /DEBUG"
    CACHE STRING "default C++ compile flags" FORCE)
set(CMAKE_CXX_FLAGS_DEBUG 
    "/MTd /Ob0 /Od" 
    CACHE STRING "default C++ compile flags for debug build" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE 
    "/MT /O2 /Ob2 /DNDEBUG" 
    CACHE STRING "default C++ compile flags for release build" FORCE)
set(CMAKE_C_FLAGS 
    "/DWIN32 /D_WINDOWS /W3 /WX /GR /GS- /Gy /FAcs /Z7 /DEBUG"
    CACHE STRING "default C++ compile flags" FORCE)
set(CMAKE_C_FLAGS_DEBUG
    "/MTd /Ob0 /Od" 
    CACHE STRING "default C++ compile flags for debug build" FORCE)
set(CMAKE_C_FLAGS_RELEASE 
    "/MT /O2 /Ob2 /DNDEBUG" 
    CACHE STRING "default C++ compile flags for release build" FORCE)

message(STATUS "CMAKE_CXX_FLAGS=" ${CMAKE_CXX_FLAGS})
message(STATUS "CMAKE_CXX_FLAGS_DEBUG=" ${CMAKE_CXX_FLAGS_DEBUG})
message(STATUS "CMAKE_CXX_FLAGS_RELEASE=" ${CMAKE_CXX_FLAGS_RELEASE})
message(STATUS "CMAKE_C_FLAGS=" ${CMAKE_CXX_FLAGS})
message(STATUS "CMAKE_C_FLAGS_DEBUG=" ${CMAKE_CXX_FLAGS_DEBUG})
message(STATUS "CMAKE_C_FLAGS_RELEASE=" ${CMAKE_C_FLAGS_RELEASE})

# Set ouput folder
if (BUILD_ARC_X8632) 
    set(MMLOADER_OUT ${CMAKE_SOURCE_DIR}/output/mmloader/x86)
elseif(BUILD_ARC_X8664)
    set(MMLOADER_OUT ${CMAKE_SOURCE_DIR}/output/mmloader/x64)
else()
    message(FATAL_ERROR "Unsupported Architecture")
endif()
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${MMLOADER_OUT}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${MMLOADER_OUT}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${MMLOADER_OUT}/bin)

# Enable solution folders
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Definitions
add_definitions(-D_WIN32_WINNT=0x0600) # Windows Vista +

# Include paths
include_directories(src/mmloader)

# create static library project
add_library(${PROJECT_NAME} STATIC
    src/mmloader/mmloader.h
    src/mmloader/mmloader.c
)

# header
set_target_properties(${PROJECT_NAME}
    PROPERTIES
        PUBLIC_HEADER "src/mmloader/mmloader.h"
)

# Add post build event to copy the header files
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/output/mmloader/include
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/src/mmloader/mmLoader.h ${CMAKE_SOURCE_DIR}/output/mmloader/include/
)

# install lib and header files
install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/mmloader
)

# Shellcode generator project
if ((NOT DEFINED BUILD_SHELLCODE_GEN) OR (BUILD_SHELLCODE_GEN STREQUAL "")  OR (${BUILD_SHELLCODE_GEN} MATCHES "(FALSE|false|0|OFF)"))
    option(BUILD_SHELLCODE_GEN "Generate the shellcode header files" OFF)
elseif(${BUILD_SHELLCODE_GEN} MATCHES "(TRUE|true|1|null|ON)")
    option(BUILD_SHELLCODE_GEN "Generate the shellcode header files" ON)
else()
    message(FATAL_ERROR "++++++++++ INVALID FLAG BUILD_SHELLCODE_GEN=" ${BUILD_SHELLCODE_GEN})
endif()

if (BUILD_SHELLCODE_GEN)
    add_subdirectory(tools/shellcode-generator)
endif()

# Demo project
if ((NOT DEFINED BUILD_MMLOADER_DEMO) OR (BUILD_MMLOADER_DEMO STREQUAL "")  OR (${BUILD_MMLOADER_DEMO} MATCHES "(FALSE|false|0|OFF)"))
    option(BUILD_MMLOADER_DEMO "Build the aps demo" OFF)
elseif(${BUILD_MMLOADER_DEMO} MATCHES "(TRUE|true|1|null|ON)")
    option(BUILD_MMLOADER_DEMO "Build the aps demo" ON)
else()
    message(FATAL_ERROR "++++++++++ INVALID FLAG BUILD_MMLOADER_DEMO=" ${BUILD_MMLOADER_DEMO})
endif()

if (BUILD_MMLOADER_DEMO)
    add_subdirectory(demo) 
endif() 
