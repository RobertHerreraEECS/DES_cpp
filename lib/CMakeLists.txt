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
  cryptdes
  main.cpp
)
target_link_libraries(cryptdes des_src)

add_subdirectory(unittests)
