struct My_IMAGE_FILE_HEADER {
    WORD    Machine;           // Architecture (ex: 0x014C pour x86, 0x8664 pour x64)
    WORD    NumberOfSections; 
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
}