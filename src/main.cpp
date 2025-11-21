#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <windows.h>

#include "header/PeStruct.h"
#include "header/DOS_HEADERS_READ.h"

// IMPORTANT : The RvaToFileOffset function MUST be defined and functional for the rest of the document.
DWORD RvaToFileOffset(DWORD Rva, const My_IMAGE_FILE_HEADER& fileHeader, const std::vector<My_IMAGE_SECTION_HEADER>& sections) {

    return 0; 
} 


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_dll>" << std::endl;
        return 1;
    }

    std::fstream file(argv[1], std::ios::in | std::ios::binary);
    if (!file) {
        std::cerr << "Error: unable to open The DLL." << std::endl;
        return 1;
    }


    // 1. reading the DOS Header
    My_IMAGE_DOS_HEADER dosHeader;
    file.read((char*)&dosHeader, sizeof(dosHeader));

    // 2. reading the NT Header
    file.seekg(dosHeader.e_lfanew);
    My_IMAGE_NT_HEADERS ntHeaders; 
    file.read((char*)&ntHeaders.Signature, sizeof(ntHeaders.Signature));
    file.read((char*)&ntHeaders.FileHeader, sizeof(ntHeaders.FileHeader));
    
    // read the Optional Header
    if (ntHeaders.FileHeader.SizeOfOptionalHeader > 0) {
        file.read((char*)&ntHeaders.OptionalHeader32, ntHeaders.FileHeader.SizeOfOptionalHeader);
    }
    
    // 3.read the sections 
    long sectionTableOffset = dosHeader.e_lfanew + 
                              sizeof(ntHeaders.Signature) + 
                              sizeof(ntHeaders.FileHeader) + 
                              ntHeaders.FileHeader.SizeOfOptionalHeader;

    file.seekg(sectionTableOffset);

    std::vector<My_IMAGE_SECTION_HEADER> sections; 
    sections.resize(ntHeaders.FileHeader.NumberOfSections);

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        file.read((char*)&sections[i], sizeof(My_IMAGE_SECTION_HEADER)); /
    
    // 4. processing of  Exports
    DWORD exportTableRVA = ntHeaders.OptionalHeader32.DataDirectory[0].VirtualAddress;

    if (exportTableRVA != 0) {
        DWORD exportTableFileOffset = RvaToFileOffset(exportTableRVA, ntHeaders.FileHeader, sections);
        
        // read the export struct
        IMAGE_EXPORT_DIRECTORY exportDir;
        file.seekg(exportTableFileOffset);
        file.read((char*)&exportDir, sizeof(exportDir));

        // Calcul offset file of the 3 table 
        DWORD FuncAddrOffset = RvaToFileOffset(exportDir.AddressOfFunctions, ntHeaders.FileHeader, sections);
        DWORD namePtrOffset = RvaToFileOffset(exportDir.AddressOfNames, ntHeaders.FileHeader, sections);
        DWORD nameOrdinalOffset = RvaToFileOffset(exportDir.AddressOfNameOrdinals, ntHeaders.FileHeader, sections); 

        std::cout << "\n--- Exported Functions (" << exportDir.NumberOfNames << " per name) ---" << std::endl;

        // EAT (Export Address Table) - RVA of every func
        std::vector<DWORD> functionAddresses(exportDir.NumberOfFunctions);
        file.seekg(FuncAddrOffset);
        file.read((char*)functionAddresses.data(), exportDir.NumberOfFunctions * sizeof(DWORD)); 

        // ENPT (Export Name Pointer Table) - RVA to name
        std::vector<DWORD> namePointers(exportDir.NumberOfNames); 
        file.read((char*)namePointers.data(), exportDir.NumberOfNames * sizeof(DWORD)); 

        // EOT (Export Ordinal Table) - Index to l'EAT
        std::vector<WORD> nameOrdinals(exportDir.NumberOfNames);
        file.seekg(nameOrdinalOffset);
        file.read((char*)nameOrdinals.data(), exportDir.NumberOfNames * sizeof(WORD));
        
        // 5. loop and start of disassembler
        for (DWORD i = 0; i < exportDir.NumberOfNames; ++i) {
            DWORD nameRVA = namePointers[i];
            DWORD nameOffset = RvaToFileOffset(nameRVA, ntHeaders.FileHeader, sections);

            if (nameOffset != 0) {
                char functionName[256] = {0};
                file.seekg(nameOffset);
                file.read(functionName, sizeof(functionName) - 1);

                WORD functionIndex = nameOrdinals[i];
                DWORD functionRVA = functionAddresses[functionIndex];

                std::cout << std::left << std::setw(30) << functionName
                          << " -> RVA: 0x" << std::hex << functionRVA << std::dec << std::endl;

                // start the disasm
                if (i == 0) {
                     DisassembleFunction(file, functionRVA, ntHeaders.FileHeader, sections, 100);
                }
            }
        }
    } else {
        std::cerr << "any table found" << std::endl;
    }
    
    return 0;
}