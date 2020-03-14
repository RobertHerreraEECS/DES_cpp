include_directories(src)
link_directories(src)

# C src code
set(SRC_DIR src)

add_library(des_src
	encryption.cpp
 	${SRC_DIR}/desEncrypt.c
)

# main executable
add_executable(
  main
  main.cpp
)
target_link_libraries(main des_src)

add_subdirectory(unittests)
