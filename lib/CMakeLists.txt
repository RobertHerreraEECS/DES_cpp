
include_directories(src/)
link_directories(src/)
add_subdirectory(src)

add_executable(main main.cpp
   src/desEncrypt.c
   src/BitPermutationFunctions.c
)

#add_compile_options(-fmain) #enables concepts(unstable). 

