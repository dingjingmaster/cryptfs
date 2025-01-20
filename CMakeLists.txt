cmake_minimum_required(VERSION 3.29)
project(cryptfs C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig)

pkg_check_modules(UUID   REQUIRED uuid)
pkg_check_modules(GIO    REQUIRED gio-2.0)
pkg_check_modules(CRYPT  REQUIRED libcryptsetup)

add_executable(cryptfs main.c cryptfs.c cryptfs.h sm3.c sm3.h)
target_link_libraries(cryptfs PUBLIC ${GIO_LIBRARIES} ${UUID_LIBRARIES} ${CRYPT_LIBRARIES})
target_include_directories(cryptfs PUBLIC ${GIO_INCLUDE_DIRS} ${UUID_INCLUDE_DIRS} ${CRYPT_INCLUDE_DIRS})
