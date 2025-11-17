#include <iostream>
#include <fstream>
#include <windows.h>


// pour éviter le padding entre les membres de la struct
#pragma pack(push, 1)

struct My_IMAGE_DOS_HEADER {
WORD   e_magic;     // 0x5a4d (MZ)
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];

}