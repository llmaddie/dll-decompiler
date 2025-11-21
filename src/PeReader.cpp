#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

#include "header/PeStruct.h"


int main() {
    IMAGE_EXPORT_DIRECTORY exportDir;
    file.seekg(exportTableFileOffset);
    file.read((char*)&exportDir, sizeof(exportDir));

    // calcul offset file of the 3 tableaux
    DWORD FuncAddrOffset = RvaToFileOffset(exportDir.AdressOfFunctions, fileHeader, sections);
    DWORD namePtrOffset = RvaToFileOffset(exportDir.AdressOfFunctions, fileHeader, sections);
    DWORD nameOrdinaryOffset = RvaToFileOffset(exportDir.AdressOfFunctions, fileHeader, sections);

    std::cout << "\n--- Exported Functions (" << exportDir.NumberOfNames << "  per name) ---" << std::endl;

    // read the table 
    std::vector<DWORD> namePointers(exportDir.NumberOfNames);
    file.seekg(namePtrOffset);
    file.read((char*)namePointers.data(), exportDir.NumberOfNames *sizeof(WORD));

    // EOT
    std::vector<WORD> nameOrdinals(exportDir.NumberOfNames);
    file.seekg(nameOrdinaryOffset);
    file.read((char*)nameOrdinals.data(), exportDir.NumberOfNames * sizeof(WORD));

    // EAT
    std::vector<DWORD> functionddresses(exportDir.NumberOfFunctions);
    file.seekg(funcAddrOffset);
    file.read((char*)functionAddresses.data(), exportDir.NumberOfFunctions * SIZEOF(DWORD));
}

// list of name 
for (DWORD i = 0; i < exportDir.NumberOfNames; ++i) {


    // take the name 
    DWORD nameRVA = namePointers[i];
    DWORD nameOffset = RvaTOFIleOffset(nameRVA, fileHeader, sections);

    if (nameOffset != 0) {
        char functionName[256] = {0}; // be careful to have an buffer length necessary
        file.seekg(nameOffset);
        file.read(functionName, sizeof(functionName) - 1);
}

// obtain the index of EAT func 
    WORD functionIndex = nameOrdinals[i];
// obtain the index of the func ( RVA code)
    DWORD functionRVA = functionAdresses[functionIndex];

        std::cout << std::left <<std::setw(30) << functionName
                  << " -> RVA: 0x" << std::hex << functionRVA
                  << " (Ordinal: " << std::dec << (exportDir.base + functionIndex) << ")"
                  << std::endl;
}