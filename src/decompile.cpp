#include <iostream>
#include <fstream>
#include <vector>
#include <capstone/capstone.h>
#include "header/PeStruct.h" 

void DisassembleFunction(std::fstream& file, DWORD functionRVA,
                        const My_IMAGE_FILE_HEADER& fileHeader,
                        const std::vector<My_IMAGE_SECTION_HEADER>& sections, 
                        size_t maxBytesToRead = 100) { 

    // 1. Convert RVA to file offset
    DWORD fileOffset = RvaToFileOffset(functionRVA, fileHeader, sections);

    if (fileOffset == 0) {
        std::cerr << "Error: RVA 0x" << std::hex << functionRVA << " is not mapped." << std::endl; // Correction
        return;
    }
    // Read the code
    std::vector<uint8_t> codeBuffer(maxBytesToRead);
    file.seekg(fileOffset);
    
    file.read((char*)codeBuffer.data(), maxBytesToRead);


    // Initialize capstone
    csh handle;
    // Choose arch
    cs_arch arch = (fileHeader.Machine == 0x8664) ? CS_ARCH_X86 : CS_ARCH_X86;
    cs_mode mode = (fileHeader.Machine == 0x8664) ? CS_MODE_64 : CS_MODE_32;

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        std::cerr << "Error with Capstone initialization" << std::endl;
        return;
    }
    // Disassm the code
    cs_insn *insn;
   
    size_t count = cs_disasm(handle, codeBuffer.data(), maxBytesToRead, functionRVA, 0, &insn);

    if (count > 0) {
        std::cout << "\n Desassemblage de la fonction (RVA: 0x" << std::hex << functionRVA << ") ---" << std::dec << std::endl;

        for (size_t i = 0; i < count; i++) {
            // print the RVA addresses
            std::cout << "0x" << std::hex << insn[i].address << ":\t"
                      << insn[i].mnemonic << "\t"
                      << insn[i].op_str << std::endl;
        }
        cs_free(insn, count);
    } else {
        std::cerr << "Error: Echec lors du désassemblage" <<std::endl;
    }
    cs_close(&handle);
} 