# ABOUTME: Build system for Unicorn-based libemu compatibility layer
# ABOUTME: Provides shellcode detection and Windows API emulation on Unicorn engine

cmake_minimum_required(VERSION 3.10)
project(unicorn-libemu-shim C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Find Unicorn library
find_package(PkgConfig REQUIRED)

# Try pkg-config first (for system-installed unicorn)
pkg_check_modules(UNICORN unicorn)

# If pkg-config didn't find it, try Python-installed unicorn
if(NOT UNICORN_FOUND)
    message(STATUS "Unicorn not found via pkg-config, trying Python installation...")

    # Find Python3 (may already be found by main CMakeLists.txt, or we find it now)
    if(NOT Python3_FOUND)
        find_package(Python3 COMPONENTS Interpreter Development)
    endif()

    if(NOT Python3_FOUND)
        message(FATAL_ERROR "Python3 not found. Cannot locate Python-installed unicorn. Please install Python3 or use system unicorn package.")
    endif()

    # Query Python for unicorn installation location
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import unicorn, os; print(os.path.dirname(unicorn.__file__))"
        OUTPUT_VARIABLE UNICORN_PYTHON_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE UNICORN_PYTHON_RESULT
    )

    if(UNICORN_PYTHON_RESULT EQUAL 0)
        message(STATUS "Found Python unicorn at: ${UNICORN_PYTHON_DIR}")

        # Set include directory - try Python package first, then system paths
        if(EXISTS "${UNICORN_PYTHON_DIR}/include")
            set(UNICORN_INCLUDE_DIRS "${UNICORN_PYTHON_DIR}/include")
            message(STATUS "Found Unicorn headers in Python package: ${UNICORN_INCLUDE_DIRS}")
        else()
            # For Debian python3-unicorn, headers may be in standard system paths
            find_path(UNICORN_INCLUDE_DIR
                NAMES unicorn/unicorn.h
                PATHS /usr/include /usr/local/include
            )
            if(UNICORN_INCLUDE_DIR)
                set(UNICORN_INCLUDE_DIRS "${UNICORN_INCLUDE_DIR}")
                message(STATUS "Found Unicorn headers in system path: ${UNICORN_INCLUDE_DIRS}")
            else()
                message(FATAL_ERROR "Unicorn headers not found. Install libunicorn-dev or ensure headers are available.")
            endif()
        endif()

        # Find the shared library - try Python package first, then system paths
        find_library(UNICORN_LIBRARY
            NAMES unicorn libunicorn
            PATHS "${UNICORN_PYTHON_DIR}/lib" "${UNICORN_PYTHON_DIR}"
            NO_DEFAULT_PATH
        )

        # If not found in Python package, search system paths (for Debian python3-unicorn)
        if(NOT UNICORN_LIBRARY)
            find_library(UNICORN_LIBRARY
                NAMES unicorn libunicorn
            )
        endif()

        if(UNICORN_LIBRARY)
            message(STATUS "Found Unicorn library: ${UNICORN_LIBRARY}")
            set(UNICORN_LIBRARIES ${UNICORN_LIBRARY})
            set(UNICORN_FOUND TRUE)
        else()
            message(FATAL_ERROR "Found Python unicorn package but could not locate library")
        endif()
    else()
        message(FATAL_ERROR "Unicorn not found via pkg-config or Python. Please install: pip install unicorn")
    endif()
endif()

# Source files for dionaea compatibility layer
set(EMU_SOURCES
    src/emu_wrapper.c
    src/emu_getpc.c
    src/emu_shellcode.c
    src/emu_env_stubs.c
)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${UNICORN_INCLUDE_DIRS}
)

# Create static library with dionaea compatibility layer
# Note: The Windows-specific shim (emu_env_w32.cpp, etc.) is not included
# as it requires windows.h and is only needed for full Windows API emulation
add_library(emu_unicorn STATIC ${EMU_SOURCES})
target_link_libraries(emu_unicorn ${UNICORN_LIBRARIES})
target_include_directories(emu_unicorn PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${UNICORN_INCLUDE_DIRS}
)

# Compile with -fPIC since this static library is linked into shared objects
set_target_properties(emu_unicorn PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Note: emu_unicorn is a static library linked into speakeasy.so at build time
# No need to install it - the code is embedded in speakeasy.so

# Install headers for reference (optional, mainly for debugging)
install(DIRECTORY include/emu
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
