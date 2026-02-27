cmake_minimum_required(VERSION 3.26)
set(PROJECT_NAME winproc)
project(${PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE})
else()
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

# Add executable target and source files
file(GLOB_RECURSE SOURCES
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
    "${CMAKE_SOURCE_DIR}/resources.rc"
)

target_include_directories(${PROJECT_NAME} PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/src/utils"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ntdll
    dbghelp
)

# Add custom command to copy symbol server DLLs for accurate thread start address resolution
set(VS_DIAG_HUB_DIR "D:/Visual Studio/Common7/IDE/CommonExtensions/Platform/DiagnosticsHub/amd64")

# Set the target output directory (where the executable is placed)
set(TARGET_BIN_DIR "$<TARGET_FILE_DIR:${PROJECT_NAME}>")

include("${CMAKE_SOURCE_DIR}/functions.cmake")

set(FILES
    "${VS_DIAG_HUB_DIR}/dbghelp.dll"
    "${VS_DIAG_HUB_DIR}/symsrv.dll"
)

# Copy files to the build directory during post build
copy_files_post_build(${PROJECT_NAME} "${FILES}" "${TARGET_BIN_DIR}")
