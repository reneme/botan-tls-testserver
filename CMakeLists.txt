cmake_minimum_required(VERSION 3.24)

project(testserver)

# TODO: Once Botan 3.3.0 is released and the Conan2 recipe is available,
#       switch from this provisional integration to conan
add_library(Botan::Botan STATIC IMPORTED)
set_target_properties(Botan::Botan
                      PROPERTIES
                        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/3rdparty/botan/build/include
                        IMPORTED_LOCATION             ${CMAKE_SOURCE_DIR}/3rdparty/botan/libbotan-3.a)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.80.0 REQUIRED program_options)

add_executable(${PROJECT_NAME} src/main.cpp)

set_target_properties(${PROJECT_NAME}
                      PROPERTIES
                        CXX_STANDARD            20
                        EXPORT_COMPILE_COMMANDS On)

target_link_libraries(${PROJECT_NAME}
                      Botan::Botan
                      Boost::boost
                      Boost::program_options)