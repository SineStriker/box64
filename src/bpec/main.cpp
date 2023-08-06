#include <iostream>
#include <cinttypes>

#include <fcntl.h>

#include "libelfin/elf++.hh"

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
    auto src_file = fopen(get_file_name(argv[1]).data(), "w");
    if (!src_file) {
        std::cout << "Cannot create source file." << std::endl;
        return -1;
    }

    

    return 0;
}