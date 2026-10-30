cmake_minimum_required(VERSION 3.20)

project(Jargonet VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(JARGONET_BUILD_TESTS "Build Jargonet tests" ON)
set(JARGONET_SODIUM_ROOT "" CACHE PATH "Prefix containing libsodium headers and libraries")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# libsodium
# ---------------------------------------------------------------------------
set(_sodium_hints)
set(_sodium_lib_hints)
if(JARGONET_SODIUM_ROOT)
  list(APPEND _sodium_hints "${JARGONET_SODIUM_ROOT}/include")
  list(APPEND _sodium_lib_hints "${JARGONET_SODIUM_ROOT}/lib")
endif()

find_path(SODIUM_INCLUDE_DIR sodium.h HINTS ${_sodium_hints})
find_library(SODIUM_LIBRARY NAMES sodium libsodium HINTS ${_sodium_lib_hints})

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
  message(FATAL_ERROR
    "libsodium was not found.\n"
    "Install it with your package manager (apt install libsodium-dev, brew install libsodium, "
    "vcpkg install libsodium) or build it from source and pass "
    "-DJARGONET_SODIUM_ROOT=<prefix>.\n"
    "Windows from-source helper: scripts/build-libsodium-msys.sh")
endif()

message(STATUS "libsodium include: ${SODIUM_INCLUDE_DIR}")
message(STATUS "libsodium library: ${SODIUM_LIBRARY}")

add_library(sodium::sodium UNKNOWN IMPORTED)
set_target_properties(sodium::sodium PROPERTIES
  IMPORTED_LOCATION "${SODIUM_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
set(JARGONET_SOURCES
  src/core/crypto.cpp
  src/core/encoding.cpp
  src/core/file_util.cpp
  src/core/identity.cpp
  src/core/msgpack.cpp
  src/core/packet.cpp
  src/net/endpoint.cpp
  src/net/rendezvous.cpp
  src/net/rendezvous_server.cpp
  src/net/stun.cpp
  src/net/udp_socket.cpp
  src/routing/onion.cpp
  src/session/dispatcher.cpp
  src/session/session.cpp
  src/session/session_manager.cpp
  src/storage/local_store.cpp
  src/app/invite.cpp
  src/app/node.cpp
)

add_library(jargonet_core STATIC ${JARGONET_SOURCES})
target_include_directories(jargonet_core PUBLIC src)
target_link_libraries(jargonet_core PUBLIC sodium::sodium)
target_compile_definitions(jargonet_core PUBLIC
  JARGONET_VERSION="${PROJECT_VERSION}"
  $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>
  $<$<PLATFORM_ID:Windows>:NOMINMAX>)

if(MSVC)
  target_compile_options(jargonet_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(jargonet_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(MINGW)
  # Produce self-contained binaries instead of depending on whichever
  # libstdc++/libgcc/winpthread happens to be first on PATH.
  add_link_options(-static)
endif()

if(WIN32)
  target_link_libraries(jargonet_core PUBLIC ws2_32 advapi32 iphlpapi bcrypt)
endif()

find_package(Threads REQUIRED)
target_link_libraries(jargonet_core PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------
add_executable(jargonet src/main.cpp src/ui/console.cpp)
target_link_libraries(jargonet PRIVATE jargonet_core)

add_executable(jargonet-rendezvous src/rendezvous_server_main.cpp)
target_link_libraries(jargonet-rendezvous PRIVATE jargonet_core)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(JARGONET_BUILD_TESTS)
  enable_testing()

  set(_jn_tests
    test_crypto
    test_msgpack
    test_packet
    test_identity
    test_store
    test_onion
    test_session
    test_rendezvous
    test_integration
  )

  foreach(_test ${_jn_tests})
    add_executable(${_test} tests/${_test}.cpp tests/test_util.hpp)
    target_link_libraries(${_test} PRIVATE jargonet_core)
    add_test(NAME ${_test} COMMAND ${_test})
    set_tests_properties(${_test} PROPERTIES TIMEOUT 120)
  endforeach()
endif()
