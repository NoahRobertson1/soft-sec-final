cmake_minimum_required(VERSION 3.20)

project(soft_sec_final)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

FetchContent_Declare(
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG master
)
FetchContent_MakeAvailable(minhook)

FetchContent_Declare(
        tiny_aes
        GIT_REPOSITORY https://github.com/kokke/tiny-AES-c.git
        GIT_TAG master
)
FetchContent_MakeAvailable(tiny_aes)

add_library(tiny_aes_lib
        ${tiny_aes_SOURCE_DIR}/aes.c
)

set_target_properties(tiny_aes_lib PROPERTIES
        LINKER_LANGUAGE C
)

target_include_directories(tiny_aes_lib PUBLIC
        ${tiny_aes_SOURCE_DIR}
)

add_executable(soft_sec_final
        main.cpp
        player/Player.cpp
        protection/Protection.cpp
        util/Util.cpp
        communication/Communication.cpp
        communication/Communication.h
)

target_link_libraries(soft_sec_final PRIVATE
        minhook
        tiny_aes_lib
        psapi
)

target_link_options(soft_sec_final PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
)

set_target_properties(soft_sec_final PROPERTIES
        WIN32_EXECUTABLE FALSE
)


target_link_options(soft_sec_final PRIVATE -s) # remove debug symbols