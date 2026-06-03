cmake_minimum_required(VERSION 3.10)
project(microjson
        VERSION     0.4.2
        DESCRIPTION "Minimal JSON parser (benchmark fork of cJSON, intentionally vulnerable)"
        LANGUAGES   C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Optional features ────────────────────────────────────────────────────────
option(ENABLE_ASAN     "Build with AddressSanitizer"            OFF)
option(ENABLE_AFL      "Build with AFL++ instrumentation"        OFF)
option(MICROJSON_JWT   "Enable JWT verification via OpenSSL"     OFF)
option(BUILD_TESTING   "Build the regression test runner"        ON)

# ── Sources ──────────────────────────────────────────────────────────────────
set(LIB_SOURCES src/json_parser.c)
set(MAIN_SOURCES src/main.c)

include_directories(include)

add_library(microjson STATIC ${LIB_SOURCES})
target_include_directories(microjson PUBLIC include)

add_executable(json_parser ${MAIN_SOURCES})
target_link_libraries(json_parser microjson)

# ── Optional OpenSSL linkage (declared so Agent A picks up the dependency) ──
if(MICROJSON_JWT)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(microjson PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(microjson PUBLIC MICROJSON_HAVE_JWT=1)
endif()

# ── Sanitizer / fuzzer instrumentation ──────────────────────────────────────
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O0)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_AFL)
    set(CMAKE_C_COMPILER afl-clang-fast)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O1)
    add_link_options(-fsanitize=address)
endif()

# ── Install ──────────────────────────────────────────────────────────────────
install(TARGETS json_parser microjson
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include/microjson)

# ── Tests ────────────────────────────────────────────────────────────────────
if(BUILD_TESTING)
    enable_testing()
    add_test(
        NAME    parse_seed_01
        COMMAND json_parser ${CMAKE_SOURCE_DIR}/seeds/seed_01.json)
    add_test(
        NAME    parse_seed_02
        COMMAND json_parser ${CMAKE_SOURCE_DIR}/seeds/seed_02.json)
    add_test(
        NAME    parse_seed_03
        COMMAND json_parser ${CMAKE_SOURCE_DIR}/seeds/seed_03.json)
endif()
