cmake_minimum_required(VERSION 3.13)
project(ebpf-example C)

set(CMAKE_C_STANDARD 11)

# Find clang
find_program(CLANG_EXECUTABLE clang REQUIRED)

# Set output directory for BPF object
set(BPF_OUTPUT ${CMAKE_BINARY_DIR}/src)
file(MAKE_DIRECTORY ${BPF_OUTPUT})

# Compile eBPF program
add_custom_command(
    OUTPUT ${BPF_OUTPUT}/example.bpf.o
    COMMAND ${CLANG_EXECUTABLE}
        -target bpf
        -D__TARGET_ARCH=x86
        -O2 -g
        -I /usr/include
        -c ${CMAKE_SOURCE_DIR}/src/example.bpf.c
        -o ${BPF_OUTPUT}/example.bpf.o
    DEPENDS ${CMAKE_SOURCE_DIR}/src/example.bpf.c
    COMMENT "Compiling eBPF program"
)

add_custom_target(bpf_objects ALL DEPENDS ${BPF_OUTPUT}/example.bpf.o)

# Build user-space loader
add_executable(loader src/main.c)
target_include_directories(loader PRIVATE /usr/include)
target_link_libraries(loader bpf)
add_dependencies(loader bpf_objects)

# Copy BPF object next to loader for runtime loading
add_custom_command(TARGET loader POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${BPF_OUTPUT}/example.bpf.o
            ${CMAKE_CURRENT_BINARY_DIR}/example.bpf.o
)

