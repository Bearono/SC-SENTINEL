cmake_minimum_required(VERSION 3.10)
project(modlite
        VERSION     3.1.6
        DESCRIPTION "Minimal Modbus TCP parser, benchmark fork of libmodbus (intentionally vulnerable)"
        LANGUAGES   C)

set(CMAKE_C_STANDARD 99)

option(ENABLE_ASAN   "Build with AddressSanitizer"      OFF)
option(ENABLE_AFL    "Build with AFL++ instrumentation" OFF)
option(MODLITE_TLS   "Enable Modbus/TCP-Secure via OpenSSL" OFF)
option(BUILD_TESTING "Build regression smoke tests"     ON)

include_directories(include)

add_library(modbus_proto_lib STATIC src/modbus_proto.c)
target_include_directories(modbus_proto_lib PUBLIC include)

add_executable(modbus_parser src/main.c)
target_link_libraries(modbus_parser modbus_proto_lib)

if(MODLITE_TLS)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(modbus_proto_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(modbus_proto_lib PUBLIC MODLITE_HAVE_TLS=1)
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

install(TARGETS modbus_parser modbus_proto_lib
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include/modlite)

if(BUILD_TESTING)
    enable_testing()
    add_test(NAME parse_seed_01 COMMAND modbus_parser ${CMAKE_SOURCE_DIR}/seeds/seed_01.bin)
    add_test(NAME parse_seed_02 COMMAND modbus_parser ${CMAKE_SOURCE_DIR}/seeds/seed_02.bin)
endif()
