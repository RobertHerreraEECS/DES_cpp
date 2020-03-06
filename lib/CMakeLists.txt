
include_directories(src/)
link_directories(src/)
add_subdirectory(src)

add_executable(main main.cpp
   src/desEncrypt.c
)

add_compile_options(-std=c++11 -stdlib=libc++)

