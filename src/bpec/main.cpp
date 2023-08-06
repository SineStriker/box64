#include <iostream>
#include <cinttypes>

#include <fcntl.h>

#include "libelfin/elf++.hh"

#include "x64emu.h"

#include "box64_headers.h"

static std::string get_file_name(const std::string &path) {
    auto idx = path.find_last_of('/');
    if (idx == std::string::npos)
        return path;
    return path.substr(idx + 1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: bpec [executable]" << std::endl;
        return 0;
    }

    // 1. Open executable, find text section
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    elf::elf f(elf::create_mmap_loader(fd));
    const auto &sec = f.get_section(".text");
    if (!sec.valid()) {
        std::cout << "Section .text not found." << std::endl;
        return -1;
    }

    const auto &data = sec.data();
    const auto &size = sec.size();

    // 2. Generate code
    auto src_name = get_file_name(argv[1]) + "_bpec";
    auto src_file = fopen((src_name + ".cpp").data(), "w");
    if (!src_file) {
        std::cout << "Cannot create source file." << std::endl;
        return -1;
    }

    fprintf(src_file, "%s\n", x64emu_headers);
    fprintf(src_file, "%s\n", R"(

#include <stdio.h>

extern "C" {

__attribute__((visibility("default"))) int BPEC_ShouldRun(size_t offset) {
    return 1;
}

static bool visited = false;

__attribute__((visibility("default"))) void BPEC_Run(x64emu_t *emu) {
    if (visited)
        return;

    visited = true;

    printf("OK\n");
}

}

    )");

    fclose(src_file);

    // 3. Compile code
    int ret = system(("g++ -std=c++17 -shared -O3 -o " + src_name + ".so " + src_name + ".cpp").data());
    if (ret != 0) {
        printf("Compile failed with code %d\n", ret);
    }

    return 0;
}