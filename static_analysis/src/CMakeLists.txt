cmake_minimum_required(VERSION 3.13.4)
project(ARCS)

#===============================================================================
# LOAD LLVM CONFIGURATION
#===============================================================================
# Set this to a valid LLVM installation dir
set(LT_LLVM_INSTALL_DIR "" CACHE PATH "LLVM installation directory")

# Add the location of LLVMConfig.cmake to CMake search paths (so that
# find_package can locate it)
list(APPEND CMAKE_PREFIX_PATH "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")

# FIXME: This is a warkaround for #25. Remove once resolved and use
# find_package(LLVM 11.0.0 REQUIRED CONFIG) instead.
find_package(LLVM REQUIRED CONFIG)


# HelloWorld includes headers from LLVM - update the include paths accordingly
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS} 
"${CMAKE_SOURCE_DIR}/SVF/include"
"${CMAKE_SOURCE_DIR}/spdlog/include")

message("${CMAKE_SOURCE_DIR}/SVF/include")


#===============================================================================
# BUILD CONFIGURATION
#===============================================================================
# Use the same C++ standard as LLVM does
set(CMAKE_CXX_STANDARD 14 CACHE STRING "")

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

#===============================================================================
# ADD THE TARGET
#===============================================================================
set(PASSES
  src
    )
  
set(arcs_SOURCES
  arcs-main.cpp
  )

file (GLOB arcs_HEADERS "../include/*.h")
#foreach( pass ${PASSES} )
# Create a library corresponding to 'plugin'
add_library( arcs MODULE
  ${arcs_HEADERS}
  ${arcs_SOURCES}
)

# On Darwin (unlike on Linux), undefined symbols in shared objects are not
# allowed at the end of the link-edit. The plugins defined here:
#  - _are_ shared objects
#  - reference symbols from LLVM shared libraries, i.e. symbols which are
#    undefined until those shared objects are loaded in memory (and hence
#    _undefined_ during static linking)
# The build will fail with errors like this:
#    "Undefined symbols for architecture x86_64"
# with various LLVM symbols being undefined. Since those symbols are later
# loaded and resolved at runtime, these errors are false positives.
# This behaviour can be modified via the '-undefined' OS X linker flag as
# follows.
#message(${CMAKE_SOURCE_DIR})
target_link_libraries(arcs PUBLIC
  "${src}"
)
                                                                                                                                                                                                                                                                                                                                                                                              