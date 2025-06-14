#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
int main() {
    struct bpf_object *obj;
    int err;

    obj = bpf_object__open_file("example.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_title(obj, "tracepoint/syscalls/sys_enter_execve");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        return 1;
    }

    // Attach to tracepoint
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach program\n");
        return 1;
    }

    printf("eBPF program attached. Press Ctrl+C to exit.\n");
    while (1) sleep(1);
}

