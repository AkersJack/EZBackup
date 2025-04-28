cmake_minimum_required(VERSION 3.10.0)
set(CMAKE_C_STANDARD 17)

project(ezBackup 
        VERSION 0.1.0 
        LANGUAGES C
        DESCRIPTION "An easy backup solution")



# Ensures CMake is generating debug builds by default
set(CMAKE_BUILD_TYPE Debug)


# add_subdirectory(test)

# Find libarchive
find_package(LibArchive REQUIRED)

# Test File (general testing going to switch to try to test everything here)
add_executable(testing test.c)

# Main (client)
add_executable(ezBackup main.c tools.c database.c)

# Link executable with libarchive
target_link_libraries(ezBackup PRIVATE archive PRIVATE sqlite3 PRIVATE cjson)

# Server 
add_executable(server test_server.c config.c server.c)
target_link_libraries(server PRIVATE archive PRIVATE cjson PRIVATE crypto)

# Menu 
add_executable(menu menu.c)
target_link_libraries(menu PRIVATE ncurses)

# SFTP 
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSSH2 REQUIRED libssh2)
add_executable(sftp test_sftp.c sftp.c config.c)
target_include_directories(sftp PRIVATE ${LIBSSH2_INCLUDE_DIRS})
target_link_libraries(sftp PRIVATE archive PRIVATE cjson PRIVATE crypto PRIVATE ${LIBSSH2_LIBRARIES})

# Database 
add_executable(database test_database.c database.c tools.c config.c)
target_link_libraries(database PRIVATE sqlite3 PRIVATE cjson)


# Enable debugging
add_compile_options(-g)

# Config
add_library(config STATIC config.c)
target_link_libraries(config PRIVATE cjson)

# set(CMAKE_C_FLAGS_DEBUG "-g") # could do set(CMAGE_BUILD_TYPE Debug)

target_compile_options(database PRIVATE -g)

set(CMAKE_C_FLAGS "-g -O0")  # Disable optimizations for better debugging


# Enable Tests
include(CTest)
# add_subdirectory(ezBackup)
if(BUILD_TESTING)
        # add_executable(tests tests.c)
endif()

# enable_testing()


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
