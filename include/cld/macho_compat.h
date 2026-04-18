#ifndef CLD_MACHO_COMPAT_H
#define CLD_MACHO_COMPAT_H

#if defined(__APPLE__)
#include <mach-o/arm64/reloc.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/x86_64/reloc.h>
#include <mach/machine.h>
#else

#include <stdint.h>

typedef int32_t cpu_type_t;
typedef int32_t cpu_subtype_t;

#define CPU_TYPE_X86_64 ((cpu_type_t) 0x01000007)
#define CPU_TYPE_ARM64  ((cpu_type_t) 0x0100000c)

#define CPU_SUBTYPE_X86_64_ALL ((cpu_subtype_t) 3)
#define CPU_SUBTYPE_ARM64_ALL  ((cpu_subtype_t) 0)

#define MH_MAGIC_64 0xfeedfacfu

#define MH_OBJECT  0x1u
#define MH_EXECUTE 0x2u

#define MH_NOUNDEFS 0x00000001u
#define MH_DYLDLINK 0x00000004u
#define MH_TWOLEVEL 0x00000080u
#define MH_PIE      0x00200000u

#define LC_REQ_DYLD      0x80000000u
#define LC_SEGMENT_64    0x19u
#define LC_SYMTAB        0x2u
#define LC_DYSYMTAB      0xbu
#define LC_LOAD_DYLIB    0xcu
#define LC_LOAD_DYLINKER 0xeu
#define LC_CODE_SIGNATURE 0x1du
#define LC_MAIN          (LC_REQ_DYLD | 0x28u)
#define LC_BUILD_VERSION 0x32u

#define PLATFORM_MACOS 1u

#define SEG_TEXT     "__TEXT"
#define SEG_DATA     "__DATA"
#define SEG_LINKEDIT "__LINKEDIT"
#define SEG_PAGEZERO "__PAGEZERO"

#define SECTION_TYPE       0x000000ffu
#define SECTION_ATTRIBUTES 0xffffff00u

#define S_REGULAR  0x0u
#define S_ZEROFILL 0x1u

#define S_ATTR_PURE_INSTRUCTIONS 0x80000000u
#define S_ATTR_SOME_INSTRUCTIONS 0x00000400u
#define S_ATTR_DEBUG             0x02000000u

#define NO_SECT 0u

#define N_STAB 0xe0u
#define N_TYPE 0x0eu
#define N_EXT  0x01u

#define N_UNDF 0x0u
#define N_ABS  0x2u
#define N_SECT 0xeu

#define ARM64_RELOC_UNSIGNED          0u
#define ARM64_RELOC_SUBTRACTOR        1u
#define ARM64_RELOC_BRANCH26          2u
#define ARM64_RELOC_PAGE21            3u
#define ARM64_RELOC_PAGEOFF12         4u
#define ARM64_RELOC_GOT_LOAD_PAGE21   5u
#define ARM64_RELOC_GOT_LOAD_PAGEOFF12 6u
#define ARM64_RELOC_ADDEND            10u

#define X86_64_RELOC_UNSIGNED 0u
#define X86_64_RELOC_SIGNED   1u
#define X86_64_RELOC_BRANCH   2u
#define X86_64_RELOC_SIGNED_1 6u
#define X86_64_RELOC_SIGNED_2 7u
#define X86_64_RELOC_SIGNED_4 8u

struct mach_header_64 {
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t maxprot;
    int32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};

struct build_version_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct lc_str {
    uint32_t offset;
};

struct dylib {
    struct lc_str name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    struct dylib dylib;
};

struct dylinker_command {
    uint32_t cmd;
    uint32_t cmdsize;
    struct lc_str name;
};

struct entry_point_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};

struct nlist_64 {
    union {
        uint32_t n_strx;
    } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

struct relocation_info {
    int32_t r_address;
    uint32_t r_symbolnum : 24,
             r_pcrel : 1,
             r_length : 2,
             r_extern : 1,
             r_type : 4;
};

#endif

#endif