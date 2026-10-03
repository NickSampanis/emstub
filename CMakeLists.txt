# Protocol headers shared by the stub, dbgeng and the GUI.
add_library(emstub_proto INTERFACE)
target_include_directories(emstub_proto INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Stub core. Embedders outside this build (Bochs, QEMU, kernels) just compile src/stub.c
# with include/ on the include path.
add_library(emstub STATIC src/stub.c)
target_link_libraries(emstub PUBLIC emstub_proto)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(emstub PRIVATE -Wall -Wextra -Wdeclaration-after-statement)
endif()

# Fake x86-64 target over TCP, for developing dbgeng and the GUI without an emulator.
add_executable(emstub_fake_target tools/fake_target.c)
target_link_libraries(emstub_fake_target PRIVATE emstub)
if(WIN32)
    target_link_libraries(emstub_fake_target PRIVATE ws2_32)
    target_compile_definitions(emstub_fake_target PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Host-side test: fake x86 target + in-memory transport.
option(EMSTUB_BUILD_TESTS "Build the emstub loopback test" ON)
if(EMSTUB_BUILD_TESTS)
    add_executable(emstub_loopback tests/loopback.c)
    target_link_libraries(emstub_loopback PRIVATE emstub)
    add_test(NAME emstub_loopback COMMAND emstub_loopback)
endif()
