# neuromz-protocol — the NeuroMZ protocol 2 (PROTOCOL.md), its wire format in
# C (the nmzp library), the shared test vectors and the conformance suite.
#
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build                  libnmzp, nmz-conformance, the tests
#   ctest --test-dir build               unit tests, the vectors, a short fuzz run
#   build/nmz-conformance --host 127.0.0.1:8470 --token TOKEN
#
# Used by neuromz-server and neuromz-cli through FetchContent (or a local
# checkout): they link nmzp::nmzp; the tests and the conformance program are
# built only when this is the top project or NMZP_BUILD_CONFORMANCE is on.
cmake_minimum_required(VERSION 3.21)
project(neuromz_protocol VERSION 2.0.0 DESCRIPTION "The NeuroMZ protocol 2: spec, C wire library, test vectors, conformance suite"
        LANGUAGES C)

# The version string: CMake's VERSION holds numbers only, so the whole string
# (2.0.0-dev until the first release, docs/DESIGN.md P38-P39) is here and in
# include/nmzp.h (NMZP_VERSION, NMZP_VERSION_MAJOR/MINOR/PATCH); they must
# agree with each other and with the VERSION above. The wire protocol has
# its own number (NMZP_PROTOCOL_MAJOR, 2).
set(NMZP_VERSION_STRING "2.0.0-dev")
file(STRINGS "${PROJECT_SOURCE_DIR}/include/nmzp.h" _nmzp_h REGEX "^#define NMZP_VERSION(_MAJOR|_MINOR|_PATCH)? ")
if(NOT _nmzp_h STREQUAL "#define NMZP_VERSION \"${NMZP_VERSION_STRING}\";#define NMZP_VERSION_MAJOR ${PROJECT_VERSION_MAJOR};#define NMZP_VERSION_MINOR ${PROJECT_VERSION_MINOR};#define NMZP_VERSION_PATCH ${PROJECT_VERSION_PATCH}"
   OR NOT NMZP_VERSION_STRING MATCHES "^${PROJECT_VERSION}(-|$)")
  message(FATAL_ERROR "include/nmzp.h (${_nmzp_h}) does not match the version here (${PROJECT_VERSION}, ${NMZP_VERSION_STRING})")
endif()

option(NMZP_WERROR "Treat compiler warnings as errors" ON)
option(NMZP_SANITIZE "AddressSanitizer + UndefinedBehaviorSanitizer (GCC/Clang)" OFF)
option(NMZP_BUILD_TESTS "Build the unit and fuzz tests" ${PROJECT_IS_TOP_LEVEL})
option(NMZP_BUILD_CONFORMANCE "Build nmz-conformance" ${PROJECT_IS_TOP_LEVEL})

if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_library(nmzp_warnings INTERFACE)
if(MSVC)
  target_compile_options(nmzp_warnings INTERFACE /W4 /wd4244 /wd4267 /utf-8 $<$<BOOL:${NMZP_WERROR}>:/WX>)
  target_compile_definitions(nmzp_warnings INTERFACE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(nmzp_warnings INTERFACE -Wall -Wextra -pedantic -Wshadow -Wstrict-prototypes
                                                 -Wmissing-prototypes -Wvla $<$<BOOL:${NMZP_WERROR}>:-Werror>)
endif()
if(NMZP_SANITIZE)
  if(MSVC)
    message(FATAL_ERROR "NMZP_SANITIZE is for GCC/Clang")
  endif()
  target_compile_options(nmzp_warnings INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer
                                                 -fno-sanitize-recover=all)
  target_link_options(nmzp_warnings INTERFACE -fsanitize=address,undefined)
endif()

add_library(nmzp STATIC src/buf.c src/mpack.c src/frame.c src/sock.c src/client.c src/util.c src/json.c)
add_library(nmzp::nmzp ALIAS nmzp)
target_include_directories(nmzp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(nmzp PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_link_libraries(nmzp PRIVATE nmzp_warnings)
if(WIN32)
  target_link_libraries(nmzp PUBLIC ws2_32 bcrypt)
else()
  target_link_libraries(nmzp PUBLIC m)
endif()

if(NMZP_BUILD_CONFORMANCE)
  add_executable(nmz-conformance conformance/conformance.c)
  set_target_properties(nmz-conformance PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(nmz-conformance PRIVATE nmzp nmzp_warnings)
endif()

if(NMZP_BUILD_TESTS)
  enable_testing()
  add_executable(test_wire tests/test_wire.c)
  add_executable(fuzz_wire tests/fuzz.c)
  add_executable(nmz-vectors tests/vectors.c)
  foreach(t test_wire fuzz_wire nmz-vectors)
    set_target_properties(${t} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_link_libraries(${t} PRIVATE nmzp nmzp_warnings)
  endforeach()
  add_test(NAME wire COMMAND test_wire)
  # the committed vectors pass, and this implementation writes exactly them
  add_test(NAME vectors COMMAND nmz-vectors check ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors)
  add_test(NAME vectors-written COMMAND ${CMAKE_COMMAND} -DVECTORS=$<TARGET_FILE:nmz-vectors>
           -DSRC=${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors -DOUT=${CMAKE_CURRENT_BINARY_DIR}/vectors-fresh
           -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors_same.cmake)
  add_test(NAME fuzz COMMAND fuzz_wire 200000 12345)
endif()
