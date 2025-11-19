#include <iostream>
#include <fstream>
#include <stdint.h>
#include <windows.h>

// const 
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;
typedef uint64_t ULONGLONG;

// data directory : 
#pragma pack(push, 1)
struct IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;   // rva 
    DWORD Size;
};
#pragma pack(pop)
// --- IMAGE SECTION HEADERS --- 
#pragma pack(push, 1)
struct MY_IMAGE_SECTION_HEADERS {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME]; // name of the section 
    union {
        DWORD PhysicalAdress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAdress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocation;
    DWORD PointerToLineNumbers;
    WORD  NumberOfRelocations;
    WORD NumberOfLineNumbers;
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
    ULONGLONG SizeOfStackReserve; // ULONGLONG = 8 octets 
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