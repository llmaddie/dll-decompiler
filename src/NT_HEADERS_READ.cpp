#include <windows.h>
#pragma pack(push, 1)
struct My_IMAGE_FILE_HEADER {
    WORD    Machine;           // Architecture (ex: 0x014C pour x86, 0x8664 pour x64)
    WORD    NumberOfSections; 
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
};
#pragma pack(pop)

#pragma pack(push, 1)

struct My_IMAGE_NT_HEADERS {
    DWORD Signature; // 0x00004550 ('PE\0\0')
    My_IMAGE_FILE_HEADER FileHeader; 
};
#pragma pack(pop)
#pragma pack(push, 1)
struct IMAGE_OPTIONAL_HEADER_COMMON {
    WORD    Magic;                      // 0x10B (PE32) ou 0x20B (PE32+)
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
};
#pragma pack(pop)
#pragma pack(push, 1)

struct My_IMAGE_OPTIONAL_HEADER32 {
    // Adresse (4 octets)
    DWORD   AddressOfEntryPoint;        // Où commence l'exécution (RVA)
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    // Adresses de base de limage  en mémoire (4 octets)
    DWORD   ImageBase;      
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    
    DWORD   SizeOfImage;                
    DWORD   NumberOfRvaAndSizes;        // Nombre d'entrées dans le DataDirectory
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

#pragma pack(pop)

#pragma pack(push, 1)

struct My_IMAGE_OPTIONAL_HEADER64 {
    ULONGLONG AddressOfEntryPoint;      
    ULONGLONG BaseOfCode;

    // Adresses de base de l'image en mémoire (8 octets)
    ULONGLONG ImageBase;              
    DWORD   SectionAlignment;
    DWORD   FileAlignment;

    DWORD   SizeOfImage;                
    // ...

    DWORD   NumberOfRvaAndSizes;       
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
#pragma pack(pop)
#pragma pack(push, 1)
struct My_IMAGE_OPTIONNAL_HEADER32 {
    // champs commun identique au ceux précedent 
    // adresse de 4 octets 
    DWORD AddressOfEntryPoint;      // where start the RVA execution
    DWORD BaseOfCode;
    DWORD BaseOfData;

    // adresse of base image 4 octets
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    // .... optionnal other like version, os etc... 

    DWORD SizeOfImage;
    /// ... 
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

#pragma pack(pop)

#pragma pack(push, 1)

struct My_IMAGE_DATA_DIRECTORY {
        DWORD VirtualAdresses;           // RVA of the table
        DWORD  Size;
};
#pragma pack(pop)