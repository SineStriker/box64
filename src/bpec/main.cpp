#include <cinttypes>
#include <iostream>
#include <map>
#include <set>
#include <unordered_map>

#include <fcntl.h>

#include "libelfin/elf++.hh"

#include "x64emu.h"

#include "box64_headers.h"

#include <capstone/capstone.h>

static std::string get_file_name(const std::string &path) {
    auto idx = path.find_last_of('/');
    if (idx == std::string::npos)
        return path;
    return path.substr(idx + 1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable> [options]\n", get_file_name(argv[0]).data());
        printf("\n");
        printf("Options:\n");
        printf("    %-15s %s\n", "-r", "Reserve source file");
        return 0;
    }

    // options
    bool opt_reserveSrcFile = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-r")) {
            opt_reserveSrcFile = true;
        }
    }

    auto src_name = get_file_name(argv[1]) + "_bpec";
    auto src_file_name = src_name + ".cpp";

    //---------------------------------------------------------------------
    // 1. Open executable and find text section
    //---------------------------------------------------------------------
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

    const auto &data = reinterpret_cast<const uint8_t *>(sec.data());
    const auto &size = sec.size();
    const auto &entry = sec.get_hdr().offset;

    auto isLocalCall = [=](uint64_t addr) -> bool {
        return addr >= entry && addr <= entry + size; // Otherwise the address is in .plt
    };

    printf("Text section offset: %lx\n", sec.get_hdr().offset);
    printf("Text section size: %lx\n", size);
    printf("\n");

    //---------------------------------------------------------------------
    // 2. Disassable code
    //---------------------------------------------------------------------
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to open capstone handle!\n");
        return -1;
    }

    // enable detail mode
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, data, size, entry, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            printf("0x%" PRIx64 ":\t%s\t\t%s\t%d\n", insn[j].address, insn[j].mnemonic, insn[j].op_str, insn[j].id);
        }
    } else {
        printf("ERROR: Failed to disassemble given code!\n");
        return -1;
    }

    //---------------------------------------------------------------------
    // 3. Generate source file
    //---------------------------------------------------------------------
    auto src_file = fopen(src_file_name.data(), "w");
    if (!src_file) {
        std::cout << "Cannot create source file." << std::endl;
        return -1;
    }

    // get jump table
    std::unordered_map<uint64_t, const cs_insn *> allInstrs;
    allInstrs.reserve(count);
    for (size_t i = 0; i < count; i++) {
        allInstrs.insert(std::make_pair(insn[i].address, &insn[i]));
    }

    printf("Jump Table: \n");

    const cs_insn *lastInstr = nullptr;
    std::map<uint64_t, const cs_insn *> jumpTargets;
    for (size_t i = 0; i < count; i++) {
        const auto &instr = insn[i];
        const auto &x86 = instr.detail->x86;

        if (instr.id == X86_INS_ENDBR32 || instr.id == X86_INS_ENDBR64 || lastInstr) {
            jumpTargets.insert(std::make_pair(instr.address, &instr));
        }

        lastInstr = nullptr;
        for (int j = 0; j < instr.detail->groups_count; ++j) {
            switch (instr.detail->groups[j]) {
                case X86_GRP_JUMP:
                case X86_GRP_CALL:
                    lastInstr = &instr;
                    if (x86.operands[0].type == X86_OP_IMM) {
                        auto addr = X86_REL_ADDR(instr);
                        auto it = allInstrs.find(addr);
                        if (it != allInstrs.end()) {
                            jumpTargets.insert(std::make_pair(addr, it->second));
                        }
                    }
                    break;
                case X86_GRP_RET:
                    lastInstr = &instr;
                    break;
                default:
                    break;
            }
        }
    }

    std::vector<std::vector<const cs_insn *>> basicBlocks;
    for (auto it = jumpTargets.begin(); it != jumpTargets.end(); ++it) {
        auto it1 = std::next(it);

        decltype(basicBlocks)::value_type blocks;
        for (auto instr = it->second; instr != insn + count && (it1 == jumpTargets.end() || instr != it1->second);
             ++instr) {
            blocks.push_back(instr);
        }

        if (blocks.empty())
            continue;

        basicBlocks.emplace_back(blocks);
    }

    for (size_t i = 0; i < basicBlocks.size(); ++i) {
        printf("Basic block %ld: size %ld\n", i, basicBlocks[i].size());
        printf("Address: 0x%lx\n", basicBlocks[i].front()->address);
        for (const auto &instr : std::as_const(basicBlocks[i])) {
            printf("%s ", instr->mnemonic);
        }
        printf("\n\n");
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

    cs_free(insn, count);
    cs_close(&handle);

    //---------------------------------------------------------------------
    // 4. Compile
    //---------------------------------------------------------------------
    int ret = system(("g++ -std=c++17 -shared -O3 -o " + src_name + ".so " + src_file_name).data());

    // remove file
    if (!opt_reserveSrcFile) {
        std::remove(src_file_name.data());
    }

    if (ret != 0) {
        printf("Compile failed with code %d\n", ret);
        return ret;
    }

    return 0;
}