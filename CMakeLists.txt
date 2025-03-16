cmake_minimum_required(VERSION 3.10.0)
set(CMAKE_C_STANDARD 17)

project(ezBackup 
        VERSION 0.1.0 
        LANGUAGES C
        DESCRIPTION "An easy backup solution")


# add_subdirectory(test)

# Find libarchive
find_package(LibArchive REQUIRED)

# Main (client)
add_executable(ezBackup main.c tools.c database.c)

# Link executable with libarchive
target_link_libraries(ezBackup PRIVATE archive PRIVATE sqlite3)

# Server 
add_executable(server server.c)
target_link_libraries(server PRIVATE archive PRIVATE cjson PRIVATE crypto)

# Database 
add_executable(database test_database.c database.c tools.c)
target_link_libraries(database PRIVATE sqlite3)

# Enable debugging
add_compile_options(-g)
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
