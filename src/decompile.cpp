#include <windows.h> 
#include "include.h"

std::fstream file("Dll_test.dll", std::ios::in | std::ios::binary);

// read the DOS header
IMAGE_DOS_HEADER dosHeader;
file.read((char*)&dosHeader, sizeof(IMAGE_DOS_HEADER));

// go to NT header location
file.seekg(dosHeader.e_lfanew);

// read the NT header
IMAGE_NT_HEADERS ntHeaders;
file.read((char*)&ntHeaders, sizeof(IMAGE_NT_HEADERS));