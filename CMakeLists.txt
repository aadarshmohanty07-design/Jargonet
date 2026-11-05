cmake_minimum_required(VERSION 3.20)

project(Jargonet LANGUAGES CXX)

# The submission binary for this deadline is meshchat. The historical Jargonet
# sources remain in the tree for reference but are not part of this build.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

add_subdirectory(meshchat)
