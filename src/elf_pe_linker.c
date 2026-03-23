#include "cld/linker.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#define CLD_ELF_MAGIC0 0x7f
#define CLD_ELF_MAGIC1 'E'
#define CLD_ELF_MAGIC2 'L'
#define CLD_ELF_MAGIC3 'F'

#define CLD_ELFCLASS64 2
#define CLD_ELFDATA2LSB 1
#define CLD_ET_REL 1
#define CLD_ET_EXEC 2
#define CLD_EM_AARCH64 183

#define CLD_SHT_PROGBITS 1
#define CLD_SHT_SYMTAB 2
#define CLD_SHT_RELA 4
#define CLD_SHT_NOBITS 8

#define CLD_SHF_ALLOC 0x2u

#define CLD_R_AARCH64_ADR_PREL_PG_HI21 275u
#define CLD_R_AARCH64_ADD_ABS_LO12_NC 277u
#define CLD_R_AARCH64_CALL26 283u

#define CLD_PT_LOAD 1u

#define CLD_PE_MACHINE_ARM64 0xaa64u
#define CLD_PE_MAGIC_PE32_PLUS 0x20bu
#define CLD_PE_SUBSYSTEM_WINDOWS_CUI 3u

typedef struct {
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
} CldElfShdr;

typedef struct {
    uint32_t name;
    uint8_t info;
    uint8_t other;
    uint16_t shndx;
    uint64_t value;
    uint64_t size;
} CldElfSym;

typedef struct {
    uint64_t offset;
    uint64_t info;
    int64_t addend;
} CldElfRela;

typedef struct {
    uint8_t *file_data;
    size_t file_size;
    CldElfShdr *shdrs;
    size_t shnum;
    const char *shstr;
    size_t shstr_size;
    CldElfSym *symtab;
    size_t sym_count;
    const char *strtab;
    size_t strtab_size;
} CldElfObject;

typedef struct {
    size_t object_index;
    size_t input_shndx;
    const CldElfShdr *shdr;
    const char *name;
    uint64_t out_addr;
    uint64_t out_file_off;
    uint8_t *out_ptr;
} CldLinkedSection;

static uint16_t cld_read_u16le(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t cld_read_u32le(const uint8_t *p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                      ((uint32_t)p[3] << 24));
}

static uint64_t cld_read_u64le(const uint8_t *p) {
    uint64_t lo = cld_read_u32le(p);
    uint64_t hi = cld_read_u32le(p + 4);
    return lo | (hi << 32);
}

static void cld_write_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void cld_write_u32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void cld_write_u64le(uint8_t *p, uint64_t v) {
    cld_write_u32le(p, (uint32_t)(v & 0xffffffffu));
    cld_write_u32le(p + 4, (uint32_t)(v >> 32));
}

static bool cld_patch_branch26(uint8_t *contents, uint64_t place, uint64_t target,
                               CldError *error) {
    uint32_t instruction = cld_read_u32le(contents);
    int64_t delta = (int64_t)target - (int64_t)place;
    int64_t immediate;

    if ((delta & 0x3) != 0) {
        cld_set_error(error, "branch target is not 4-byte aligned");
        return false;
    }

    immediate = delta >> 2;
    if (immediate < -(1ll << 25) || immediate >= (1ll << 25)) {
        cld_set_error(error, "branch relocation target is out of range");
        return false;
    }

    instruction &= 0xfc000000u;
    instruction |= (uint32_t)(immediate & 0x03ffffffu);
    cld_write_u32le(contents, instruction);
    return true;
}

static bool cld_patch_page21(uint8_t *contents, uint64_t place, uint64_t target,
                             CldError *error) {
    uint32_t instruction = cld_read_u32le(contents);
    int64_t page_delta =
        (int64_t)(target & ~0xfffull) - (int64_t)(place & ~0xfffull);
    int64_t immediate = page_delta >> 12;
    uint32_t immlo;
    uint32_t immhi;

    if (immediate < -(1ll << 20) || immediate >= (1ll << 20)) {
        cld_set_error(error, "page21 relocation target is out of range");
        return false;
    }

    immlo = (uint32_t)(immediate & 0x3);
    immhi = (uint32_t)((immediate >> 2) & 0x7ffff);
    instruction &= ~((uint32_t)(0x3u << 29) | (uint32_t)(0x7ffffu << 5));
    instruction |= (immlo << 29) | (immhi << 5);
    cld_write_u32le(contents, instruction);
    return true;
}

static bool cld_patch_pageoff12(uint8_t *contents, uint64_t target,
                                CldError *error) {
    uint32_t instruction = cld_read_u32le(contents);
    uint64_t offset_in_page = target & 0xfffu;
    uint64_t scale;
    uint64_t immediate;

    if ((instruction & 0x1f000000u) == 0x11000000u)
        scale = 1ull;
    else
        scale = 4ull;

    if ((offset_in_page % scale) != 0) {
        cld_set_error(error,
                      "pageoff12 relocation target is not aligned for the instruction scale");
        return false;
    }

    immediate = offset_in_page / scale;
    if (immediate > 0xfff) {
        cld_set_error(error, "pageoff12 relocation target is out of range");
        return false;
    }

    instruction &= ~(0xfffu << 10);
    instruction |= (uint32_t)(immediate << 10);
    cld_write_u32le(contents, instruction);
    return true;
}

static const char *cld_elf_section_name(const CldElfObject *obj,
                                        const CldElfShdr *sh) {
    if (!obj || !sh || !obj->shstr || sh->name >= obj->shstr_size)
        return "";
    return obj->shstr + sh->name;
}

static bool cld_parse_elf_object(const char *path, CldElfObject *out,
                                 CldError *error) {
    uint8_t *data = NULL;
    size_t size = 0;
    uint64_t e_shoff;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
    size_t i;

    memset(out, 0, sizeof(*out));
    if (!cld_read_entire_file(path, &data, &size, error))
        return false;

    if (size < 64) {
        cld_set_error(error, "%s is too small to be an ELF64 file", path);
        free(data);
        return false;
    }
    if (data[0] != CLD_ELF_MAGIC0 || data[1] != CLD_ELF_MAGIC1 ||
        data[2] != CLD_ELF_MAGIC2 || data[3] != CLD_ELF_MAGIC3) {
        cld_set_error(error, "%s is not an ELF file", path);
        free(data);
        return false;
    }
    if (data[4] != CLD_ELFCLASS64 || data[5] != CLD_ELFDATA2LSB) {
        cld_set_error(error, "%s is not ELF64 little-endian", path);
        free(data);
        return false;
    }
    if (cld_read_u16le(data + 16) != CLD_ET_REL) {
        cld_set_error(error, "%s is not a relocatable ELF object", path);
        free(data);
        return false;
    }
    if (cld_read_u16le(data + 18) != CLD_EM_AARCH64) {
        cld_set_error(error, "%s is not an arm64 ELF object", path);
        free(data);
        return false;
    }

    e_shoff = cld_read_u64le(data + 40);
    e_shentsize = cld_read_u16le(data + 58);
    e_shnum = cld_read_u16le(data + 60);
    e_shstrndx = cld_read_u16le(data + 62);

    if (e_shentsize < 64 || e_shnum == 0 ||
        e_shoff + (uint64_t)e_shentsize * e_shnum > size) {
        cld_set_error(error, "%s has invalid section header table", path);
        free(data);
        return false;
    }

    out->shdrs = (CldElfShdr *)calloc((size_t)e_shnum, sizeof(CldElfShdr));
    if (!out->shdrs) {
        cld_set_error(error, "out of memory allocating section headers");
        free(data);
        return false;
    }

    for (i = 0; i < (size_t)e_shnum; ++i) {
        const uint8_t *sh = data + (size_t)e_shoff + i * e_shentsize;
        out->shdrs[i].name = cld_read_u32le(sh + 0);
        out->shdrs[i].type = cld_read_u32le(sh + 4);
        out->shdrs[i].flags = cld_read_u64le(sh + 8);
        out->shdrs[i].addr = cld_read_u64le(sh + 16);
        out->shdrs[i].offset = cld_read_u64le(sh + 24);
        out->shdrs[i].size = cld_read_u64le(sh + 32);
        out->shdrs[i].link = cld_read_u32le(sh + 40);
        out->shdrs[i].info = cld_read_u32le(sh + 44);
        out->shdrs[i].addralign = cld_read_u64le(sh + 48);
        out->shdrs[i].entsize = cld_read_u64le(sh + 56);
    }

    out->file_data = data;
    out->file_size = size;
    out->shnum = e_shnum;

    if (e_shstrndx >= out->shnum) {
        cld_set_error(error, "%s has invalid shstr index", path);
        return false;
    }

    {
        const CldElfShdr *shstr = &out->shdrs[e_shstrndx];
        if (shstr->offset + shstr->size > out->file_size) {
            cld_set_error(error, "%s has out-of-range shstrtab", path);
            return false;
        }
        out->shstr = (const char *)(out->file_data + shstr->offset);
        out->shstr_size = (size_t)shstr->size;
    }

    for (i = 0; i < out->shnum; ++i) {
        const CldElfShdr *sh = &out->shdrs[i];
        if (sh->type != CLD_SHT_SYMTAB)
            continue;
        if (sh->entsize < 24 || sh->offset + sh->size > out->file_size) {
            cld_set_error(error, "%s has invalid symtab", path);
            return false;
        }
        out->symtab = (CldElfSym *)(out->file_data + sh->offset);
        out->sym_count = (size_t)(sh->size / sh->entsize);
        if (sh->link >= out->shnum) {
            cld_set_error(error, "%s symtab strtab link is invalid", path);
            return false;
        }
        {
            const CldElfShdr *str = &out->shdrs[sh->link];
            if (str->offset + str->size > out->file_size) {
                cld_set_error(error, "%s has invalid strtab", path);
                return false;
            }
            out->strtab = (const char *)(out->file_data + str->offset);
            out->strtab_size = (size_t)str->size;
        }
        break;
    }

    if (!out->symtab || !out->strtab) {
        cld_set_error(error, "%s is missing symbol tables", path);
        return false;
    }

    return true;
}

static void cld_free_elf_object(CldElfObject *obj) {
    if (!obj)
        return;
    free(obj->shdrs);
    free(obj->file_data);
    memset(obj, 0, sizeof(*obj));
}

static bool cld_write_file_copy(const char *input_path, const char *output_path,
                                CldError *error) {
    uint8_t *data = NULL;
    size_t size = 0;
    bool ok;
    if (!cld_read_entire_file(input_path, &data, &size, error))
        return false;
    ok = cld_write_entire_file(output_path, data, size, error);
    free(data);
    return ok;
}

static const CldLinkedSection *cld_find_linked_section(const CldLinkedSection *secs,
                                                       size_t sec_count,
                                                       size_t object_index,
                                                       size_t shndx) {
    size_t i;
    for (i = 0; i < sec_count; ++i) {
        if (secs[i].object_index == object_index && secs[i].input_shndx == shndx)
            return &secs[i];
    }
    return NULL;
}

static bool cld_build_linked_sections(const CldElfObject *objs,
                                      size_t object_count,
                                      uint64_t image_base,
                                      uint64_t initial_file_off,
                                      CldLinkedSection **out_secs,
                                      size_t *out_count,
                                      uint8_t **out_image,
                                      size_t *out_image_size,
                                      CldError *error) {
    CldLinkedSection *secs = NULL;
    size_t sec_count = 0;
    size_t oi;
    uint64_t file_off = initial_file_off;
    uint64_t addr = image_base + initial_file_off;
    uint8_t *image;
    size_t image_size;

    for (oi = 0; oi < object_count; ++oi) {
        size_t si;
        for (si = 0; si < objs[oi].shnum; ++si) {
            const CldElfShdr *sh = &objs[oi].shdrs[si];
            if ((sh->flags & CLD_SHF_ALLOC) == 0)
                continue;
            if (sh->type != CLD_SHT_PROGBITS && sh->type != CLD_SHT_NOBITS)
                continue;
            ++sec_count;
        }
    }

    if (sec_count == 0) {
        cld_set_error(error, "no allocatable sections found in input objects");
        return false;
    }

    secs = (CldLinkedSection *)calloc(sec_count, sizeof(CldLinkedSection));
    if (!secs) {
        cld_set_error(error, "out of memory allocating linked sections");
        return false;
    }

    sec_count = 0;
    for (oi = 0; oi < object_count; ++oi) {
        size_t si;
        for (si = 0; si < objs[oi].shnum; ++si) {
            const CldElfShdr *sh = &objs[oi].shdrs[si];
            uint64_t align;
            if ((sh->flags & CLD_SHF_ALLOC) == 0)
                continue;
            if (sh->type != CLD_SHT_PROGBITS && sh->type != CLD_SHT_NOBITS)
                continue;
            align = sh->addralign ? sh->addralign : 16u;
            file_off = cld_align_up_u64(file_off, align);
            addr = cld_align_up_u64(addr, align);
            secs[sec_count].object_index = oi;
            secs[sec_count].input_shndx = si;
            secs[sec_count].shdr = sh;
            secs[sec_count].name = cld_elf_section_name(&objs[oi], sh);
            secs[sec_count].out_file_off = file_off;
            secs[sec_count].out_addr = addr;
            file_off += (sh->type == CLD_SHT_NOBITS) ? 0 : sh->size;
            addr += sh->size;
            ++sec_count;
        }
    }

    image_size = (size_t)cld_align_up_u64(file_off, 0x1000);
    image = (uint8_t *)calloc(image_size, 1);
    if (!image) {
        free(secs);
        cld_set_error(error, "out of memory allocating output image");
        return false;
    }

    for (oi = 0; oi < sec_count; ++oi) {
        const CldElfObject *obj = &objs[secs[oi].object_index];
        const CldElfShdr *sh = secs[oi].shdr;
        if (sh->type == CLD_SHT_NOBITS)
            continue;
        if (sh->offset + sh->size > obj->file_size) {
            free(image);
            free(secs);
            cld_set_error(error, "section data is out of range");
            return false;
        }
        if (secs[oi].out_file_off + sh->size > image_size) {
            free(image);
            free(secs);
            cld_set_error(error, "section output exceeds image bounds");
            return false;
        }
        memcpy(image + secs[oi].out_file_off, obj->file_data + sh->offset,
               (size_t)sh->size);
        secs[oi].out_ptr = image + secs[oi].out_file_off;
    }

    *out_secs = secs;
    *out_count = sec_count;
    *out_image = image;
    *out_image_size = image_size;
    return true;
}

static bool cld_resolve_symbol_addr(const CldElfObject *objs,
                                    size_t object_count,
                                    const CldLinkedSection *secs,
                                    size_t sec_count,
                                    size_t object_index,
                                    uint32_t sym_index,
                                    uint64_t *out_addr,
                                    CldError *error) {
    const CldElfObject *obj = &objs[object_index];
    const CldElfSym *sym;

    if (sym_index >= obj->sym_count) {
        cld_set_error(error, "relocation symbol index %u is out of range", sym_index);
        return false;
    }

    sym = &obj->symtab[sym_index];
    if (sym->shndx != 0) {
        const CldLinkedSection *sec = cld_find_linked_section(secs, sec_count, object_index, sym->shndx);
        if (!sec) {
            cld_set_error(error, "symbol references unsupported section index %u", sym->shndx);
            return false;
        }
        *out_addr = sec->out_addr + sym->value;
        return true;
    }

    if (sym->name >= obj->strtab_size) {
        cld_set_error(error, "undefined symbol has invalid string index");
        return false;
    }

    {
        const char *name = obj->strtab + sym->name;
        size_t oi;
        for (oi = 0; oi < object_count; ++oi) {
            size_t si;
            for (si = 0; si < objs[oi].sym_count; ++si) {
                const CldElfSym *candidate = &objs[oi].symtab[si];
                const CldLinkedSection *candidate_sec;
                const char *candidate_name;
                if (candidate->shndx == 0 || candidate->name >= objs[oi].strtab_size)
                    continue;
                candidate_name = objs[oi].strtab + candidate->name;
                if (strcmp(name, candidate_name) != 0)
                    continue;
                candidate_sec = cld_find_linked_section(secs, sec_count, oi, candidate->shndx);
                if (!candidate_sec)
                    continue;
                *out_addr = candidate_sec->out_addr + candidate->value;
                return true;
            }
        }
        cld_set_error(error, "undefined symbol %s is not supported", name);
        return false;
    }
}

static bool cld_apply_elf_relocations(const CldElfObject *objs,
                                      size_t object_count,
                                      const CldLinkedSection *secs,
                                      size_t sec_count,
                                      CldError *error) {
    size_t oi;

    for (oi = 0; oi < object_count; ++oi) {
        const CldElfObject *obj = &objs[oi];
        size_t i;
        for (i = 0; i < obj->shnum; ++i) {
            const CldElfShdr *rel_sh = &obj->shdrs[i];
            const CldLinkedSection *target_sec;
            size_t rela_count;
            size_t ri;

            if (rel_sh->type != CLD_SHT_RELA)
                continue;
            if (rel_sh->info >= obj->shnum)
                continue;
            if (rel_sh->offset + rel_sh->size > obj->file_size || rel_sh->entsize < 24)
                continue;

            target_sec = cld_find_linked_section(secs, sec_count, oi, rel_sh->info);
            if (!target_sec || !target_sec->out_ptr)
                continue;

            rela_count = (size_t)(rel_sh->size / rel_sh->entsize);
            for (ri = 0; ri < rela_count; ++ri) {
                const uint8_t *rp = obj->file_data + rel_sh->offset + ri * rel_sh->entsize;
                CldElfRela rela;
                uint32_t r_type;
                uint32_t r_sym;
                uint64_t target;
                uint64_t place;
                uint8_t *fixup;

                rela.offset = cld_read_u64le(rp + 0);
                rela.info = cld_read_u64le(rp + 8);
                rela.addend = (int64_t)cld_read_u64le(rp + 16);
                r_type = (uint32_t)(rela.info & 0xffffffffu);
                r_sym = (uint32_t)(rela.info >> 32);

                if (rela.offset + 4 > target_sec->shdr->size) {
                    cld_set_error(error, "relocation offset is out of section bounds");
                    return false;
                }

                if (!cld_resolve_symbol_addr(objs, object_count, secs, sec_count, oi,
                                             r_sym, &target, error)) {
                    return false;
                }
                target = (uint64_t)((int64_t)target + rela.addend);
                place = target_sec->out_addr + rela.offset;
                fixup = target_sec->out_ptr + rela.offset;

                switch (r_type) {
                    case CLD_R_AARCH64_CALL26:
                        if (!cld_patch_branch26(fixup, place, target, error))
                            return false;
                        break;
                    case CLD_R_AARCH64_ADR_PREL_PG_HI21:
                        if (!cld_patch_page21(fixup, place, target, error))
                            return false;
                        break;
                    case CLD_R_AARCH64_ADD_ABS_LO12_NC:
                        if (!cld_patch_pageoff12(fixup, target, error))
                            return false;
                        break;
                    default:
                        cld_set_error(error, "unsupported ELF relocation type %u", r_type);
                        return false;
                }
            }
        }
    }

    return true;
}

static bool cld_find_entry_addr(const CldElfObject *objs,
                                size_t object_count,
                                const CldLinkedSection *secs,
                                size_t sec_count,
                                const char *entry_symbol,
                                uint64_t *entry_addr,
                                CldError *error) {
    size_t oi;
    for (oi = 0; oi < object_count; ++oi) {
        size_t si;
        for (si = 0; si < objs[oi].sym_count; ++si) {
            const CldElfSym *sym = &objs[oi].symtab[si];
            const char *name;
            if (sym->shndx == 0 || sym->name >= objs[oi].strtab_size)
                continue;
            name = objs[oi].strtab + sym->name;
            if (strcmp(name, entry_symbol) != 0)
                continue;
            return cld_resolve_symbol_addr(objs, object_count, secs, sec_count,
                                           oi, (uint32_t)si, entry_addr, error);
        }
    }
    cld_set_error(error, "entry symbol '%s' not found", entry_symbol);
    return false;
}

static bool cld_write_arm64_elf_executable(const CldElfObject *objs,
                                           size_t object_count,
                                           const CldLinkOptions *options,
                                           CldError *error) {
    CldLinkedSection *secs = NULL;
    size_t sec_count = 0;
    uint8_t *image = NULL;
    size_t image_size = 0;
    uint64_t image_base =
        options->target->image_base ? options->target->image_base : 0x400000ull;
    uint64_t entry_addr = 0;

    if (!cld_build_linked_sections(objs, object_count, image_base, 0x1000, &secs,
                                   &sec_count, &image, &image_size, error)) {
        return false;
    }

    if (!cld_apply_elf_relocations(objs, object_count, secs, sec_count, error)) {
        free(image);
        free(secs);
        return false;
    }

    if (!cld_find_entry_addr(objs, object_count, secs, sec_count,
                             options->entry_symbol, &entry_addr, error)) {
        free(image);
        free(secs);
        return false;
    }

    memset(image, 0, 0x1000);
    image[0] = CLD_ELF_MAGIC0;
    image[1] = CLD_ELF_MAGIC1;
    image[2] = CLD_ELF_MAGIC2;
    image[3] = CLD_ELF_MAGIC3;
    image[4] = CLD_ELFCLASS64;
    image[5] = CLD_ELFDATA2LSB;
    image[6] = 1;
    cld_write_u16le(image + 16, CLD_ET_EXEC);
    cld_write_u16le(image + 18, CLD_EM_AARCH64);
    cld_write_u32le(image + 20, 1);
    cld_write_u64le(image + 24, entry_addr);
    cld_write_u64le(image + 32, 64);
    cld_write_u64le(image + 40, 0);
    cld_write_u32le(image + 48, 0);
    cld_write_u16le(image + 52, 64);
    cld_write_u16le(image + 54, 56);
    cld_write_u16le(image + 56, 1);
    cld_write_u16le(image + 58, 0);
    cld_write_u16le(image + 60, 0);
    cld_write_u16le(image + 62, 0);

    cld_write_u32le(image + 64, CLD_PT_LOAD);
    cld_write_u32le(image + 68, 0x7);
    cld_write_u64le(image + 72, 0);
    cld_write_u64le(image + 80, image_base);
    cld_write_u64le(image + 88, image_base);
    cld_write_u64le(image + 96, image_size);
    cld_write_u64le(image + 104, image_size);
    cld_write_u64le(image + 112, 0x1000);

    if (!cld_write_entire_file(options->output_path, image, image_size, error)) {
        free(image);
        free(secs);
        return false;
    }

#ifndef _WIN32
    (void)chmod(options->output_path, 0755);
#endif

    free(image);
    free(secs);
    return true;
}

static bool cld_write_arm64_pe_executable(const CldElfObject *objs,
                                          size_t object_count,
                                          const CldLinkOptions *options,
                                          CldError *error) {
    CldLinkedSection *secs = NULL;
    size_t sec_count = 0;
    uint8_t *linked = NULL;
    size_t linked_size = 0;
    uint64_t image_base = 0x140000000ull;
    uint64_t entry_addr = 0;
    uint32_t section_alignment = 0x1000u;
    uint32_t file_alignment = 0x200u;
    uint32_t headers_size = 0x200u;
    uint32_t section_rva = section_alignment;
    uint32_t section_raw_ptr = headers_size;
    uint32_t section_virtual_size;
    uint32_t section_raw_size;
    uint32_t size_of_image;
    uint8_t *out;
    size_t out_size;

    if (!cld_build_linked_sections(objs, object_count, image_base, section_raw_ptr,
                                   &secs, &sec_count, &linked, &linked_size,
                                   error)) {
        return false;
    }

    if (!cld_apply_elf_relocations(objs, object_count, secs, sec_count, error)) {
        free(linked);
        free(secs);
        return false;
    }

    if (!cld_find_entry_addr(objs, object_count, secs, sec_count,
                             options->entry_symbol, &entry_addr, error)) {
        free(linked);
        free(secs);
        return false;
    }

    section_virtual_size =
        (uint32_t)(linked_size > headers_size ? (linked_size - headers_size) : 0);
    section_raw_size = (uint32_t)cld_align_up_u64(section_virtual_size, file_alignment);
    size_of_image = (uint32_t)cld_align_up_u64((uint64_t)section_rva + section_virtual_size,
                                               section_alignment);
    out_size = section_raw_ptr + section_raw_size;
    out = (uint8_t *)calloc(out_size, 1);
    if (!out) {
        free(linked);
        free(secs);
        cld_set_error(error, "out of memory allocating PE image");
        return false;
    }

    out[0] = 'M';
    out[1] = 'Z';
    cld_write_u32le(out + 0x3c, 0x80u);

    out[0x80] = 'P';
    out[0x81] = 'E';
    out[0x82] = 0;
    out[0x83] = 0;

    cld_write_u16le(out + 0x84, CLD_PE_MACHINE_ARM64);
    cld_write_u16le(out + 0x86, 1);
    cld_write_u32le(out + 0x88, 0);
    cld_write_u32le(out + 0x8c, 0);
    cld_write_u32le(out + 0x90, 0);
    cld_write_u16le(out + 0x94, 0xf0);
    cld_write_u16le(out + 0x96, 0x0022);

    cld_write_u16le(out + 0x98, CLD_PE_MAGIC_PE32_PLUS);
    out[0x9a] = 0;
    out[0x9b] = 0;
    cld_write_u32le(out + 0xa8, (uint32_t)(entry_addr - image_base));
    cld_write_u32le(out + 0xac, section_rva);
    cld_write_u64le(out + 0xb0, image_base);
    cld_write_u32le(out + 0xb8, section_alignment);
    cld_write_u32le(out + 0xbc, file_alignment);
    cld_write_u16le(out + 0xc4, 6);
    cld_write_u16le(out + 0xd8, 6);
    cld_write_u32le(out + 0xdc, size_of_image);
    cld_write_u32le(out + 0xe0, headers_size);
    cld_write_u16le(out + 0xe4, CLD_PE_SUBSYSTEM_WINDOWS_CUI);
    cld_write_u16le(out + 0xe6, 0);
    cld_write_u64le(out + 0xe8, 0x100000ull);
    cld_write_u64le(out + 0xf0, 0x1000ull);
    cld_write_u64le(out + 0xf8, 0x100000ull);
    cld_write_u64le(out + 0x100, 0x1000ull);
    cld_write_u32le(out + 0x108, 0);
    cld_write_u32le(out + 0x10c, 16);

    memcpy(out + 0x188, ".text", 5);
    cld_write_u32le(out + 0x190, section_virtual_size);
    cld_write_u32le(out + 0x194, section_rva);
    cld_write_u32le(out + 0x198, section_raw_size);
    cld_write_u32le(out + 0x19c, section_raw_ptr);
    cld_write_u32le(out + 0x1ac, 0xE0000020u);

    if (section_virtual_size > 0 && linked_size > headers_size) {
        memcpy(out + section_raw_ptr, linked + headers_size,
               (size_t)section_virtual_size);
    }

    if (!cld_write_entire_file(options->output_path, out, out_size, error)) {
        free(out);
        free(linked);
        free(secs);
        return false;
    }

    free(out);
    free(linked);
    free(secs);
    return true;
}

bool cld_link_elf_like_objects(const CldMachOObject *object_files,
                               size_t object_count,
                               const CldLinkOptions *options,
                               CldError *error) {
    CldElfObject *objs;
    size_t i;
    bool is_windows_target;
    bool ok;

    if (!object_files || object_count == 0 || !options || !options->target) {
        cld_set_error(error, "invalid arguments for ELF/PE linker");
        return false;
    }

    if (options->output_kind == CLD_OUTPUT_KIND_RELOCATABLE) {
        if (object_count != 1) {
            cld_set_error(error,
                          "relocatable output currently supports a single input object for target %s",
                          options->target->name);
            return false;
        }
        return cld_write_file_copy(object_files[0].path, options->output_path, error);
    }

    objs = (CldElfObject *)calloc(object_count, sizeof(CldElfObject));
    if (!objs) {
        cld_set_error(error, "out of memory allocating ELF object list");
        return false;
    }

    for (i = 0; i < object_count; ++i) {
        if (!cld_parse_elf_object(object_files[i].path, &objs[i], error)) {
            size_t j;
            for (j = 0; j < i; ++j)
                cld_free_elf_object(&objs[j]);
            free(objs);
            return false;
        }
    }

    is_windows_target = strcmp(options->target->name, "arm64-windows") == 0;
    if (is_windows_target)
        ok = cld_write_arm64_pe_executable(objs, object_count, options, error);
    else
        ok = cld_write_arm64_elf_executable(objs, object_count, options, error);

    for (i = 0; i < object_count; ++i)
        cld_free_elf_object(&objs[i]);
    free(objs);
    return ok;
}
