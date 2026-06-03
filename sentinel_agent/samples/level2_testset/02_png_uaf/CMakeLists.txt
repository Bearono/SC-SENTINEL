cmake_minimum_required(VERSION 3.10)
project(pngreader
        VERSION     1.6.36
        DESCRIPTION "Benchmark fork of libpng (intentionally vulnerable)"
        LANGUAGES   C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(ENABLE_ASAN   "Build with AddressSanitizer"      OFF)
option(ENABLE_AFL    "Build with AFL++ instrumentation" OFF)
option(USE_SYSTEM_LIBPNG "Link against system libpng (otherwise stub)" OFF)
option(BUILD_TESTING "Build regression smoke tests"     ON)

include_directories(include)

add_library(png_loader_lib STATIC src/png_loader.c)
target_include_directories(png_loader_lib PUBLIC include)

add_executable(png_loader src/main.c)
target_link_libraries(png_loader png_loader_lib)

# ── Declare upstream dependency so Agent A can match CVE data ───────────────
if(USE_SYSTEM_LIBPNG)
    find_package(PNG  REQUIRED)
    find_package(ZLIB REQUIRED)
    target_link_libraries(png_loader_lib PUBLIC PNG::PNG ZLIB::ZLIB)
endif()

if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O0)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_AFL)
    set(CMAKE_C_COMPILER afl-clang-fast)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O1)
    add_link_options(-fsanitize=address)
endif()

install(TARGETS png_loader png_loader_lib
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include/pngreader)

if(BUILD_TESTING)
    enable_testing()
    add_test(NAME load_seed_01 COMMAND png_loader ${CMAKE_SOURCE_DIR}/seeds/seed_01.png)
    add_test(NAME load_seed_02 COMMAND png_loader ${CMAKE_SOURCE_DIR}/seeds/seed_02.png)
endif()
