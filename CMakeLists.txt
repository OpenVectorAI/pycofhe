cmake_minimum_required(VERSION 3.15)
project(${SKBUILD_PROJECT_NAME} LANGUAGES CXX)

add_subdirectory(thirdparty/CoFHE)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)

file(GLOB TENSOR_PY_BINDING_SOURCES src/tensor/*_pyb.cpp)
pybind11_add_module(tensor_core MODULE ${TENSOR_PY_BINDING_SOURCES})
target_include_directories(tensor_core
    PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/pycofhe>
    $<INSTALL_INTERFACE:include/pycofhe>)
target_link_libraries(tensor_core PRIVATE CoFHE)
install(TARGETS tensor_core DESTINATION ${SKBUILD_PROJECT_NAME}/tensor)

file(GLOB CPU_CRYPTOSYSTEM_PY_BINDING_SOURCES src/cpu_cryptosystem/*_pyb.cpp)
pybind11_add_module(cpu_cryptosystem_core MODULE ${CPU_CRYPTOSYSTEM_PY_BINDING_SOURCES})
target_include_directories(cpu_cryptosystem_core
    PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/pycofhe>
    $<INSTALL_INTERFACE:include/pycofhe>)
target_link_libraries(cpu_cryptosystem_core PRIVATE CoFHE)
install(TARGETS cpu_cryptosystem_core DESTINATION ${SKBUILD_PROJECT_NAME}/cpu_cryptosystem)

file(GLOB NETWORK_PY_BINDING_SOURCES src/network/*_pyb.cpp)
pybind11_add_module(network_core MODULE ${NETWORK_PY_BINDING_SOURCES})
target_include_directories(network_core
    PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/pycofhe>
    $<INSTALL_INTERFACE:include/pycofhe>)
target_link_libraries(network_core PRIVATE CoFHE)
install(TARGETS network_core DESTINATION ${SKBUILD_PROJECT_NAME}/network)