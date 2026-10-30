cmake_minimum_required(VERSION 3.20)

project(meshchat VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(JARGONET_SODIUM_ROOT "" CACHE PATH "Prefix containing libsodium headers and libraries")
set(SODIUM_INCLUDE_DIR "" CACHE PATH "Path containing sodium.h")
set(SODIUM_LIBRARY "" CACHE FILEPATH "libsodium library to link")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(_sodium_include_hints)
set(_sodium_lib_hints)
if(JARGONET_SODIUM_ROOT)
  list(APPEND _sodium_include_hints "${JARGONET_SODIUM_ROOT}/include")
  list(APPEND _sodium_lib_hints "${JARGONET_SODIUM_ROOT}/lib")
endif()

find_path(SODIUM_INCLUDE_DIR sodium.h HINTS ${_sodium_include_hints})
find_library(SODIUM_LIBRARY NAMES sodium libsodium HINTS ${_sodium_lib_hints})

if(WIN32 AND SODIUM_LIBRARY AND NOT SODIUM_LIBRARY MATCHES "\\.a$")
  find_library(_SODIUM_STATIC_LIBRARY NAMES libsodium.a HINTS ${_sodium_lib_hints})
  if(_SODIUM_STATIC_LIBRARY)
    set(SODIUM_LIBRARY "${_SODIUM_STATIC_LIBRARY}")
  endif()
endif()

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
  message(FATAL_ERROR
    "libsodium was not found. Install libsodium-dev / brew libsodium / vcpkg, "
    "or pass -DJARGONET_SODIUM_ROOT=<prefix> (and optionally SODIUM_LIBRARY).")
endif()

message(STATUS "meshchat libsodium include: ${SODIUM_INCLUDE_DIR}")
message(STATUS "meshchat libsodium library: ${SODIUM_LIBRARY}")

add_library(sodium::sodium UNKNOWN IMPORTED)
set_target_properties(sodium::sodium PROPERTIES
  IMPORTED_LOCATION "${SODIUM_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")

set(JARGONET_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

add_executable(meshchat
  src/main.cpp
  src/mesh_node.cpp
  ${JARGONET_ROOT}/src/core/crypto.cpp
  ${JARGONET_ROOT}/src/core/encoding.cpp
  ${JARGONET_ROOT}/src/core/msgpack.cpp
  ${JARGONET_ROOT}/src/net/endpoint.cpp
  ${JARGONET_ROOT}/src/net/udp_socket.cpp
)

target_include_directories(meshchat PRIVATE src ${JARGONET_ROOT}/src)
target_link_libraries(meshchat PRIVATE sodium::sodium)
target_compile_definitions(meshchat PRIVATE
  $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>
  $<$<PLATFORM_ID:Windows>:NOMINMAX>)

if(MSVC)
  target_compile_options(meshchat PRIVATE /W4 /permissive-)
else()
  target_compile_options(meshchat PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(MINGW)
  # Self-contained exe: do not depend on whatever libstdc++ is first on PATH.
  target_link_options(meshchat PRIVATE -static)
endif()

if(WIN32)
  target_link_libraries(meshchat PRIVATE ws2_32 advapi32 iphlpapi bcrypt)
endif()

find_package(Threads REQUIRED)
target_link_libraries(meshchat PRIVATE Threads::Threads)
