cmake_minimum_required(VERSION 3.7)

project(noah 
  VERSION 0.5.0
  LANGUAGES C CXX)

configure_file(bin/noah.in ${PROJECT_SOURCE_DIR}/bin/noah @ONLY)
configure_file(include/version.h.in ${PROJECT_SOURCE_DIR}/include/version.h)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
set(CMAKE_C_FLAGS "-Wall -Wextra -Wno-unused-parameter -std=gnu11")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g -fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")
endif()

set(Boost_USE_MULTITHREADED ON)
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
set(BOOST_ROOT "C:\\Program Files\\boost_1_65_0")
set(BOOST_INCLUDEDIR "C:\\Program Files\\boost_1_65_0")
set(BOOST_LIBRARYDIR "C:\\Program Files\\boost_1_65_0\\lib64-msvc-14.1")
set(Boost_DEBUG ON)
add_definitions( -DBOOST_ALL_NO_LIB )
add_definitions( -DBOOST_ALL_DYN_LINK )
endif()
find_package(Boost 1.65 COMPONENTS program_options REQUIRED)
link_directories(${BOOST_LIBRARYDIR})
include_directories(${BOOST_INCLUDEDIR})


add_executable(noah
  src/main.cpp
  src/vmm.c
  src/meta_strace.c
  src/base.c
  src/debug.c
  src/proc/exec.c
  src/proc/process.c
  src/mm/mm.c
  src/mm/mmap.c
)
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
target_sources(noah PUBLIC
  src/conv_windows.cpp 
  src/platform/windows/mm/mmap.cpp
)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
target_sources(noah PUBLIC
  src/conv_darwin.c 
  src/fs/darwinfs.c
  src/platform/darwin/mm/mmap.c
)
endif()

target_link_libraries(noah ${Boost_LIBRARIES})


add_subdirectory(lib/libhypervisor)
include_directories(
  include
  lib/libhypervisor/include
  ${hypervisor_BINARY_DIR}/include
)

target_link_libraries(noah hypervisor)
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
add_custom_command(TARGET noah POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:hypervisor> $<TARGET_FILE_DIR:noah>)
endif()

install(PROGRAMS bin/noah DESTINATION bin)
install(TARGETS noah DESTINATION libexec)

enable_testing()
add_subdirectory(test)
