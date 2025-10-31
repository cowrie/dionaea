# ABOUTME: CMake function to determine version from git using setuptools-scm-style versioning
# ABOUTME: Parses git describe output and formats it similar to setuptools-scm default scheme

function(get_version_from_git OUTPUT_VAR FALLBACK_VERSION)
    set(VERSION ${FALLBACK_VERSION})

    if(EXISTS ${PROJECT_SOURCE_DIR}/.git)
        find_package(Git QUIET)
        if(GIT_FOUND)
            # Get git describe output: tag-distance-hash[-dirty]
            execute_process(
                COMMAND ${GIT_EXECUTABLE} describe --tags --long --dirty --match "*[0-9]*"
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                OUTPUT_VARIABLE GIT_DESCRIBE
                ERROR_VARIABLE GIT_DESCRIBE_ERROR
                RESULT_VARIABLE TAG_RESULT
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )

            if(NOT TAG_RESULT)
                # Parse git describe output: v1.2.3-145-g469e1e5[-dirty]
                # Convert to setuptools-scm format: 1.2.3.dev145+g469e1e5[.d20251030]
                string(REGEX MATCH "^([^-]+)-([0-9]+)-g([a-f0-9]+)(-dirty)?$" MATCHED "${GIT_DESCRIBE}")

                if(MATCHED)
                    set(VERSION_TAG ${CMAKE_MATCH_1})
                    set(VERSION_DISTANCE ${CMAKE_MATCH_2})
                    set(VERSION_HASH ${CMAKE_MATCH_3})
                    set(VERSION_DIRTY ${CMAKE_MATCH_4})

                    # Strip leading 'v' if present
                    string(REGEX REPLACE "^v" "" VERSION_TAG "${VERSION_TAG}")

                    if(VERSION_DISTANCE EQUAL 0)
                        # Exact tag match
                        set(VERSION "${VERSION_TAG}")
                    else()
                        # Development version: tag.devN+ghash
                        set(VERSION "${VERSION_TAG}.dev${VERSION_DISTANCE}+g${VERSION_HASH}")
                    endif()

                    # Add dirty suffix with date if working tree is modified
                    if(VERSION_DIRTY)
                        string(TIMESTAMP DIRTY_DATE "%Y%m%d" UTC)
                        set(VERSION "${VERSION}.d${DIRTY_DATE}")
                    endif()

                    message(STATUS "Version from git: ${VERSION}")
                else()
                    message(STATUS "Could not parse git describe output: ${GIT_DESCRIBE}")
                endif()
            else()
                message(STATUS "Git describe failed (exit code ${TAG_RESULT}): ${GIT_DESCRIBE_ERROR}")
                message(STATUS "Using fallback version")
            endif()
        else()
            message(STATUS "Git not found, using fallback version")
        endif()
    else()
        message(STATUS "Not a git repository, using fallback version")
    endif()

    set(${OUTPUT_VAR} ${VERSION} PARENT_SCOPE)
endfunction()
