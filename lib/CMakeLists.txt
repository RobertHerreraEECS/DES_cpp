include_directories(src)
link_directories(src)

# C src code
set(SRC_DIR src)

# main executable
add_executable(
  main
  main.cpp
  encryption.cpp
  ${SRC_DIR}/desEncrypt.c
)

add_subdirectory(unittests)
