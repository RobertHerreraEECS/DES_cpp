add_library (des encrypt.cpp)

target_include_directories (des PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(src)

add_library(des_src SHARED
    src/desEncrypt.c
    src/desEncrypt.h
    src/encrypt.h
    src/decrypt.h
    src/permTables.h
    src/randomKeyGenerator.h
    src/BitPermutationFunctions.c
    src/BitPermutationFunctions.h
)

target_include_directories(des_src PUBLIC src)

add_executable(main_des main.cpp)
target_link_libraries(main_des des des_src)
