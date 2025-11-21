#include <stdint.h>
#include <windows.h> 

// --- define constant if windows.h was removed ---
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
// ifWindows.h wasnt include or for be sure of his lenght 
// typedef uint32_t DWORD;
// typedef uint16_t WORD;
// typedef uint8_t BYTE;
// typedef uint64_t ULONGLONG;

// Constante for the heap section
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_DOS_SIGNATURE 0x5a4d     // 'MZ'
#define IMAGE_NT_SIGNATURE  0x00004550 // 'PE\0\0'

// --- IMAGE_DATA_DIRECTORY ---
#pragma pack(push, 1)
struct IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;   // RVA
    DWORD Size;
};
#pragma pack(pop)

// --- IMAGE_EXPORT_DIRECTORY ---
#pragma pack(push, 1)
struct IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD NameRVA;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;    
    DWORD AddressOfNames;        
    DWORD AddressOfNameOrdinals; 
}; 
#pragma pack(pop)

// --- MY_IMAGE_SECTION_HEADER  ---
#pragma pack(push, 1)
struct My_IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress; 
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress; 
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations; 
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};
#pragma pack(pop)

// --- IMAGE_FILE_HEADER ---
#pragma pack(push, 1)
struct My_IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
};
#pragma pack(pop)

// --- IMAGE_OPTIONAL_HEADER32---
#pragma pack(push, 1)
struct My_IMAGE_OPTIONAL_HEADER32 {
    // ... Champs communs
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    // ---
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
#pragma pack(pop)

// --- IMAGE_OPTIONAL_HEADER64---
#pragma pack(push, 1)
struct My_IMAGE_OPTIONAL_HEADER64 {
    // ... Champs communs
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    // ---
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    // (BaseOfData not here)
    ULONGLONG ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
#pragma pack(pop)

// --- IMAGE_NT_HEADERS
#pragma pack(push, 1)
struct My_IMAGE_NT_HEADERS {
    DWORD Signature;
    My_IMAGE_FILE_HEADER FileHeader;
    union {
        My_IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        My_IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    };
};
#pragma pack(pop)