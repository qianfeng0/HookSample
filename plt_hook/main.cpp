// #include <stdio.h>
// #include <sys/mman.h>
// #include <unistd.h>
// #include <inttypes.h>
// #include <string.h>
// #include <malloc.h>

#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include <link.h>
#include <errno.h>

#include "testso.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12

#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#endif

#ifndef PAGESIZE
#define PAGESIZE PAGE_SIZE
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE-1))
#endif

#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr) + PAGE_SIZE)
#define PAGE_COVER(addr) (PAGE_END(addr) - PAGE_START(addr))

#define XH_ERRNO_UNKNOWN 1001
#define XH_ERRNO_NOTFND  1005
#define XH_ERRNO_FORMAT  1007

#define XH_LOG_INFO     printf
#define XH_LOG_ERROR    printf
#define XH_LOG_WARN     printf

#define ELF32_R_SYM(val)		((val) >> 8)
#define ELF32_R_TYPE(val)		((val) & 0xff)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))

#if defined(__LP64__)
#define XH_ELF_R_SYM(info)  ELF64_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define XH_ELF_R_SYM(info)  ELF32_R_SYM(info)
#define XH_ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

#if defined(__arm__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT      //.rel.plt
#define XH_ELF_R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT       //.rel.dyn
#define XH_ELF_R_GENERIC_ABS       R_ARM_ABS32          //.rel.dyn
#elif defined(__aarch64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_AARCH64_ABS64
#elif defined(__i386__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_386_32
#elif defined(__x86_64__)
#define XH_ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define XH_ELF_R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#define XH_ELF_R_GENERIC_ABS       R_X86_64_64
#endif

void *my_malloc(size_t size)
{
    printf("%zu bytes memory are allocated by libtest.so\n", size);
    return malloc(size);
}

int xh_util_get_mem_protect(uintptr_t addr, size_t len, const char *pathname, unsigned int *prot)
{
    uintptr_t  start_addr = addr;
    uintptr_t  end_addr = addr + len;
    FILE      *fp;
    char       line[512];
    uintptr_t  start, end;
    char       perm[5];
    int        load0 = 1;
    int        found_all = 0;

    *prot = 0;

    if(NULL == (fp = fopen("/proc/self/maps", "r"))) return -1;

    while(fgets(line, sizeof(line), fp))
    {
        if(NULL != pathname)
            if(NULL == strstr(line, pathname)) continue;

        if(sscanf(line, "%" PRIxPTR"-%" PRIxPTR" %4s ", &start, &end, perm) != 3) continue;

        if(perm[3] != 'p') continue;

        if(start_addr >= start && start_addr < end)
        {
            if(load0)
            {
                //first load segment
                if(perm[0] == 'r') *prot |= PROT_READ;
                if(perm[1] == 'w') *prot |= PROT_WRITE;
                if(perm[2] == 'x') *prot |= PROT_EXEC;
                load0 = 0;
            }
            else
            {
                //others
                if(perm[0] != 'r') *prot &= ~PROT_READ;
                if(perm[1] != 'w') *prot &= ~PROT_WRITE;
                if(perm[2] != 'x') *prot &= ~PROT_EXEC;
            }

            if(end_addr <= end)
            {
                found_all = 1;
                break; //finished
            }
            else
            {
                start_addr = end; //try to find the next load segment
            }
        }
    }

    fclose(fp);

    if(!found_all) return -1;

    return 0;
}


typedef struct
{
    const char *pathname;

    ElfW(Addr)  base_addr;
    ElfW(Addr)  bias_addr;

    ElfW(Ehdr) *ehdr;
    ElfW(Phdr) *phdr;

    ElfW(Dyn)  *dyn; //.dynamic
    ElfW(Word)  dyn_sz;

    const char *strtab; //.dynstr (string-table)
    ElfW(Sym)  *symtab; //.dynsym (symbol-index to string-table's offset)

    ElfW(Addr)  relplt; //.rel.plt or .rela.plt
    ElfW(Word)  relplt_sz;

    ElfW(Addr)  reldyn; //.rel.dyn or .rela.dyn
    ElfW(Word)  reldyn_sz;

    ElfW(Addr)  relandroid; //android compressed rel or rela
    ElfW(Word)  relandroid_sz;

    //for ELF hash
    uint32_t   *bucket;
    uint32_t    bucket_cnt;
    uint32_t   *chain;
    uint32_t    chain_cnt; //invalid for GNU hash

    //append for GNU hash
    uint32_t    symoffset;
    ElfW(Addr) *bloom;
    uint32_t    bloom_sz;
    uint32_t    bloom_shift;

    int         is_use_rela;
    int         is_use_gnu_hash;
} xh_elf_t;

typedef struct xh_core_map_info
{
    char      *pathname;
    uintptr_t  base_addr;
    xh_elf_t   elf;
} xh_core_map_info_t;

//iterator for plain PLT
typedef struct
{
    uint8_t  *cur;
    uint8_t  *end;
    int       is_use_rela;
} xh_elf_plain_reloc_iterator_t;

//registered hook info collection
// typedef struct xh_core_hook_info
// {
// #if XH_CORE_DEBUG
//     char     *pathname_regex_str;
// #endif
//     regex_t   pathname_regex;
//     char     *symbol;
//     void     *new_func;
//     void    **old_func;
//     TAILQ_ENTRY(xh_core_hook_info,) link;
// } xh_core_hook_info_t;

static ElfW(Phdr) *xh_elf_get_first_segment_by_type_offset(xh_elf_t *self, ElfW(Word) type, ElfW(Off) offset)
{
    ElfW(Phdr) *phdr;

    for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++)
    {
        if(phdr->p_type == type && phdr->p_offset == offset)
        {
            return phdr;
        }
    }
    return NULL;
}

static ElfW(Phdr) *xh_elf_get_first_segment_by_type(xh_elf_t *self, ElfW(Word) type)
{
    ElfW(Phdr) *phdr;

    for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++)
    {
        if(phdr->p_type == type)
        {
            return phdr;
        }
    }
    return NULL;
}

int xh_elf_init(xh_elf_t *self, uintptr_t base_addr, const char *pathname)
{

    //always reset
    memset(self, 0, sizeof(xh_elf_t));

    self->pathname = pathname;
    self->base_addr = (ElfW(Addr))base_addr;
    self->ehdr = (ElfW(Ehdr) *)base_addr;
    self->phdr = (ElfW(Phdr) *)(base_addr + self->ehdr->e_phoff); //segmentation fault sometimes

    printf("[debug] self->ehdr->e_phoff: %d e_phnum:%d\n", self->ehdr->e_phoff,  self->ehdr->e_phnum, self->phdr);
    printf("[debug] self->phdr: %" PRIxPTR" \n", self->phdr);
    //find the first load-segment with offset 0
    ElfW(Phdr) *phdr0 = xh_elf_get_first_segment_by_type_offset(self, PT_LOAD, 0);
    printf("[debug] phdr0 %" PRIxPTR", phdr0->p_vaddr %" PRIxPTR"\n", phdr0, phdr0->p_vaddr);

    //save load bias addr
    self->bias_addr = self->base_addr - phdr0->p_vaddr;
    printf("[debug] self->bias_addr %" PRIxPTR"\n", self->bias_addr);

    //parse dynamic-segment
    ElfW(Phdr) *dhdr = xh_elf_get_first_segment_by_type(self, PT_DYNAMIC);
    printf("[debug] dhdr %" PRIxPTR", dhdr->p_vaddr: %" PRIxPTR"\n", dhdr, dhdr->p_vaddr);

    self->dyn          = (ElfW(Dyn) *)(self->bias_addr + dhdr->p_vaddr);
    self->dyn_sz       = dhdr->p_memsz;
    ElfW(Dyn) *dyn     = self->dyn;
    ElfW(Dyn) *dyn_end = self->dyn + (self->dyn_sz / sizeof(ElfW(Dyn)));
    uint32_t  *raw;

    printf("[debug] self->dyn %" PRIxPTR", self->dyn_sz %d, num %d \n", self->dyn, self->dyn_sz, (self->dyn_sz / sizeof(ElfW(Dyn))));
    // for (; dyn < dyn_end; dyn++){
    //     printf("dyn->d_tag %d\n", dyn->d_tag);
    // }
#if (1)
    for(; dyn < dyn_end; dyn++)
    {
        printf("[debug] dyn->d_tag %d, %x, val:%" PRIxPTR"\n", dyn->d_tag, dyn->d_tag, dyn->d_un);
        switch(dyn->d_tag) //segmentation fault sometimes
        {
        case DT_NULL:
            //the end of the dynamic-section
            dyn = dyn_end;
            break;
        case DT_STRTAB:
            {
                //dyn->d_un.d_ptr 是绝对地址??
                if (dyn->d_un.d_ptr > self->bias_addr)
                    self->strtab = (const char *)(dyn->d_un.d_ptr);
                else
                    self->strtab = (const char *)(self->bias_addr + dyn->d_un.d_ptr);
                printf("self->strtab: %s\n", self->strtab);
                if((ElfW(Addr))(self->strtab) < self->base_addr) return XH_ERRNO_FORMAT;
                break;
            }
        case DT_SYMTAB:
            {
                //dyn->d_un.d_ptr 是绝对地址??
                if (dyn->d_un.d_ptr > self->bias_addr)
                    self->symtab = (ElfW(Sym) *)(dyn->d_un.d_ptr);
                else
                    self->symtab = (ElfW(Sym) *)(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))(self->symtab) < self->base_addr) return XH_ERRNO_FORMAT;
                break;
            }
        case DT_PLTREL:
            //use rel or rela?
            self->is_use_rela = (dyn->d_un.d_val == DT_RELA ? 1 : 0);
            break;
        case DT_JMPREL:
            {
                //dyn->d_un.d_ptr 是绝对地址??
                if (dyn->d_un.d_ptr > self->bias_addr)
                    self->relplt = (ElfW(Addr))(dyn->d_un.d_ptr);
                else
                    self->relplt = (ElfW(Addr))(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))(self->relplt) < self->base_addr) return XH_ERRNO_FORMAT;
                break;
            }
        case DT_PLTRELSZ:
            self->relplt_sz = dyn->d_un.d_val;
            break;
        case DT_REL:
        case DT_RELA:
            {
                //dyn->d_un.d_ptr 是绝对地址??
                if (dyn->d_un.d_ptr > self->bias_addr)
                    self->reldyn = (ElfW(Addr))(dyn->d_un.d_ptr);
                else
                    self->reldyn = (ElfW(Addr))(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))(self->reldyn) < self->base_addr) return XH_ERRNO_FORMAT;
                break;
            }
        case DT_RELSZ:
        case DT_RELASZ:
            self->reldyn_sz = dyn->d_un.d_val;
            break;
        // case DT_ANDROID_REL:
        // case DT_ANDROID_RELA:
        //     {
        //         self->relandroid = (ElfW(Addr))(self->bias_addr + dyn->d_un.d_ptr);
        //         if((ElfW(Addr))(self->relandroid) < self->base_addr) return XH_ERRNO_FORMAT;
        //         break;
        //     }
        // case DT_ANDROID_RELSZ:
        // case DT_ANDROID_RELASZ:
        //     self->relandroid_sz = dyn->d_un.d_val;
        //     break;
        case DT_HASH:
            {
                //ignore DT_HASH when ELF contains DT_GNU_HASH hash table
                if(1 == self->is_use_gnu_hash) continue;

                raw = (uint32_t *)(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))raw < self->base_addr) return XH_ERRNO_FORMAT;
                self->bucket_cnt  = raw[0];
                self->chain_cnt   = raw[1];
                self->bucket      = &raw[2];
                self->chain       = &(self->bucket[self->bucket_cnt]);
                break;
            }
        case DT_GNU_HASH:
            {
                //dyn->d_un.d_ptr 是绝对地址??
                if (dyn->d_un.d_ptr > self->bias_addr )
                    raw = (uint32_t *)(dyn->d_un.d_ptr);
                else
                    raw = (uint32_t *)(self->bias_addr + dyn->d_un.d_ptr);
                if((ElfW(Addr))raw < self->base_addr) return XH_ERRNO_FORMAT;
                self->bucket_cnt  = raw[0];
                self->symoffset   = raw[1];
                self->bloom_sz    = raw[2];
                self->bloom_shift = raw[3];
                self->bloom       = (ElfW(Addr) *)(&raw[4]);
                self->bucket      = (uint32_t *)(&(self->bloom[self->bloom_sz]));
                self->chain       = (uint32_t *)(&(self->bucket[self->bucket_cnt]));
                self->is_use_gnu_hash = 1;

                printf("DT_GNU_HASH bucket_cnt:%u, symoffset:%u, bloom_sz:%u, bloom_shift:%u\n",
                    self->bucket_cnt, self->symoffset, self->bloom_sz, self->bloom_shift);
                break;
            }
        default:
            // printf("[debug] dyn->d_tag %d should not be here\n", dyn->d_tag);
            break;
        }
    }

    //check android rel/rela
    if(0 != self->relandroid)
    {
        const char *rel = (const char *)self->relandroid;
        if(self->relandroid_sz < 4 ||
           rel[0] != 'A' ||
           rel[1] != 'P' ||
           rel[2] != 'S' ||
           rel[3] != '2')
        {
            printf("android rel/rela format error\n");
            return XH_ERRNO_FORMAT;
        }

        self->relandroid += 4;
        self->relandroid_sz -= 4;
    }

    //check elf info
    // if(0 != xh_elf_check(self))
    // {
    //     XH_LOG_ERROR("elf init check failed. %s", pathname);
    //     return XH_ERRNO_FORMAT;
    // }

#if XH_ELF_DEBUG
    xh_elf_dump(self);
#endif

    printf("init OK: %s (%s %s PLT:%u DYN:%u ANDROID:%u)\n", self->pathname,
                self->is_use_rela ? "RELA" : "REL",
                self->is_use_gnu_hash ? "GNU_HASH" : "ELF_HASH",
                self->relplt_sz, self->reldyn_sz, self->relandroid_sz);

    printf("[debug] strtab:%" PRIxPTR", symtab:%" PRIxPTR", relplt:%" PRIxPTR", reldyn:%" PRIxPTR"\n", self->strtab, self->symtab, self->relplt, self->reldyn);
#endif
    return 0;

}

//GNU hash func
static uint32_t xh_elf_gnu_hash(const uint8_t *name)
{
    uint32_t h = 5381;

    while(*name != 0)
    {
        h += (h << 5) + *name++;
    }
    return h;
}

static int xh_elf_gnu_hash_lookup_def(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    uint32_t hash = xh_elf_gnu_hash((uint8_t *)symbol);

    static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
    size_t word = self->bloom[(hash / elfclass_bits) % self->bloom_sz];
    size_t mask = 0
        | (size_t)1 << (hash % elfclass_bits)
        | (size_t)1 << ((hash >> self->bloom_shift) % elfclass_bits);

    //if at least one bit is not set, this symbol is surely missing
    if((word & mask) != mask) return XH_ERRNO_NOTFND;

    //ignore STN_UNDEF
    uint32_t i = self->bucket[hash % self->bucket_cnt];
    if(i < self->symoffset) return XH_ERRNO_NOTFND;

    //loop through the chain
    while(1)
    {
        const char     *symname = self->strtab + self->symtab[i].st_name;
        const uint32_t  symhash = self->chain[i - self->symoffset];

        if((hash | (uint32_t)1) == (symhash | (uint32_t)1) && 0 == strcmp(symbol, symname))
        {
            *symidx = i;
            XH_LOG_INFO("found %s at symidx: %u (GNU_HASH DEF)\n", symbol, *symidx);
            return 0;
        }

        //chain ends with an element with the lowest bit set to 1
        if(symhash & (uint32_t)1) break;

        i++;
    }

    return XH_ERRNO_NOTFND;
}

static int xh_elf_gnu_hash_lookup_undef(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    uint32_t i;

    for(i = 0; i < self->symoffset; i++)
    {
        const char *symname = self->strtab + self->symtab[i].st_name;
        printf("xh_elf_gnu_hash_lookup_undef symname:%s, %d \n", symname, self->symtab[i].st_name);
        if(0 == strcmp(symname, symbol))
        {
            *symidx = i;
            XH_LOG_INFO("found %s at symidx: %u (GNU_HASH UNDEF)\n", symbol, *symidx);
            return 0;
        }
    }
    return XH_ERRNO_NOTFND;
}

static int xh_elf_gnu_hash_lookup(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    if(0 == xh_elf_gnu_hash_lookup_def(self, symbol, symidx)) return 0;
    if(0 == xh_elf_gnu_hash_lookup_undef(self, symbol, symidx)) return 0;
    return XH_ERRNO_NOTFND;
}

static int xh_elf_find_symidx_by_name(xh_elf_t *self, const char *symbol, uint32_t *symidx)
{
    if(self->is_use_gnu_hash)
        return xh_elf_gnu_hash_lookup(self, symbol, symidx);
    else
        // return xh_elf_hash_lookup(self, symbol, symidx);
        return XH_ERRNO_NOTFND;
}

static void xh_elf_plain_reloc_iterator_init(xh_elf_plain_reloc_iterator_t *self,
                                             ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela)
{
    self->cur = (uint8_t *)rel;
    self->end = self->cur + rel_sz;
    self->is_use_rela = is_use_rela;
}

static void *xh_elf_plain_reloc_iterator_next(xh_elf_plain_reloc_iterator_t *self)
{
    if(self->cur >= self->end) return NULL;

    void *ret = (void *)(self->cur);
    self->cur += (self->is_use_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));
    return ret;
}

int xh_util_get_addr_protect(uintptr_t addr, const char *pathname, unsigned int *prot)
{
    return xh_util_get_mem_protect(addr, sizeof(addr), pathname, prot);
}

int xh_util_set_addr_protect(uintptr_t addr, unsigned int prot)
{
    if(0 != mprotect((void *)PAGE_START(addr), PAGE_COVER(addr), (int)prot))
        return 0 == errno ? XH_ERRNO_UNKNOWN : errno;

    return 0;
}

void xh_util_flush_instruction_cache(uintptr_t addr)
{
    __builtin___clear_cache((void *)PAGE_START(addr), (void *)PAGE_END(addr));
}

static int xh_elf_replace_function(xh_elf_t *self, const char *symbol, ElfW(Addr) addr, void *new_func, void **old_func)
{
    void         *old_addr;
    unsigned int  old_prot = 0;
    unsigned int  need_prot = PROT_READ | PROT_WRITE;
    int           r;

    //already replaced?
    //here we assume that we always have read permission, is this a problem?
    if(*(void **)addr == new_func) return 0;

    //get old prot
    if(0 != (r = xh_util_get_addr_protect(addr, self->pathname, &old_prot)))
    {
        XH_LOG_ERROR("get addr prot failed. ret: %d", r);
        return r;
    }

    if(old_prot != need_prot)
    {
        //set new prot
        if(0 != (r = xh_util_set_addr_protect(addr, need_prot)))
        {
            XH_LOG_ERROR("set addr prot failed. ret: %d", r);
            return r;
        }
    }

    //save old func
    old_addr = *(void **)addr;
    if(NULL != old_func) *old_func = old_addr;

    //replace func
    *(void **)addr = new_func; //segmentation fault sometimes

    if(old_prot != need_prot)
    {
        //restore the old prot
        if(0 != (r = xh_util_set_addr_protect(addr, old_prot)))
        {
            XH_LOG_WARN("restore addr prot failed. ret: %d", r);
        }
    }

    //clear cache
    xh_util_flush_instruction_cache(addr);

    XH_LOG_INFO("XH_HK_OK %p: %p -> %p %s %s\n", (void *)addr, old_addr, new_func, symbol, self->pathname);
    return 0;
}

static int xh_elf_find_and_replace_func(xh_elf_t *self, const char *section,
                                        int is_plt, const char *symbol,
                                        void *new_func, void **old_func,
                                        uint32_t symidx, void *rel_common,
                                        int *found)
{
    ElfW(Rela)    *rela;
    ElfW(Rel)     *rel;
    ElfW(Addr)     r_offset;
    size_t         r_info;
    size_t         r_sym;
    size_t         r_type;
    ElfW(Addr)     addr;
    int            r;

    if(NULL != found) *found = 0;

    if(self->is_use_rela)
    {
        rela = (ElfW(Rela) *)rel_common;
        r_info = rela->r_info;
        r_offset = rela->r_offset;
    }
    else
    {
        rel = (ElfW(Rel) *)rel_common;
        r_info = rel->r_info;
        r_offset = rel->r_offset;
    }

    //check sym
    r_sym = XH_ELF_R_SYM(r_info);
    if(r_sym != symidx) return 0;

    //check type
    r_type = XH_ELF_R_TYPE(r_info);

    printf("r_sym %zu, r_type: %zu\n", r_sym, r_type);
    if(is_plt && r_type != XH_ELF_R_GENERIC_JUMP_SLOT) return 0;
    if(!is_plt && (r_type != XH_ELF_R_GENERIC_GLOB_DAT && r_type != XH_ELF_R_GENERIC_ABS)) return 0;

    //we found it
    XH_LOG_INFO("found %s at %s offset: %p\n", symbol, section, (void *)r_offset);
    if(NULL != found) *found = 1;

    //do replace
    addr = self->bias_addr + r_offset;
    if(addr < self->base_addr) return XH_ERRNO_FORMAT;
    if(0 != (r = xh_elf_replace_function(self, symbol, addr, new_func, old_func)))
    {
        XH_LOG_ERROR("replace function failed: %s at %s\n", symbol, section);
        return r;
    }

    return 0;
}

int xh_elf_hook(xh_elf_t *self, const char *symbol, void *new_func, void **old_func)
{
    uint32_t                        symidx;
    void                           *rel_common;
    xh_elf_plain_reloc_iterator_t   plain_iter;
    // xh_elf_packed_reloc_iterator_t  packed_iter;
    int                             found;
    int                             r;

    // if(NULL == self->pathname)
    // {
    //     XH_LOG_ERROR("not inited\n");
    //     return XH_ERRNO_ELFINIT; //not inited?
    // }

    // if(NULL == symbol || NULL == new_func) return XH_ERRNO_INVAL;

    XH_LOG_INFO("hooking %s in %s\n", symbol, self->pathname);

    //find symbol index by symbol name
    if(0 != (r = xh_elf_find_symidx_by_name(self, symbol, &symidx))) return 0;

    printf("[debug] symbol:%s, index:%u\n", symbol, symidx);
    // //replace for .rel(a).plt
    if(0 != self->relplt)
    {
        xh_elf_plain_reloc_iterator_init(&plain_iter, self->relplt, self->relplt_sz, self->is_use_rela);
        while(NULL != (rel_common = xh_elf_plain_reloc_iterator_next(&plain_iter)))
        {
            if(0 != (r = xh_elf_find_and_replace_func(self,
                                                      (self->is_use_rela ? ".rela.plt" : ".rel.plt"), 1,
                                                      symbol, new_func, old_func,
                                                      symidx, rel_common, &found))) return r;
            if(found) break;
        }
    }

    // //replace for .rel(a).dyn
    // if(0 != self->reldyn)
    // {
    //     xh_elf_plain_reloc_iterator_init(&plain_iter, self->reldyn, self->reldyn_sz, self->is_use_rela);
    //     while(NULL != (rel_common = xh_elf_plain_reloc_iterator_next(&plain_iter)))
    //     {
    //         if(0 != (r = xh_elf_find_and_replace_func(self,
    //                                                   (self->is_use_rela ? ".rela.dyn" : ".rel.dyn"), 0,
    //                                                   symbol, new_func, old_func,
    //                                                   symidx, rel_common, NULL))) return r;
    //     }
    // }

    // //replace for .rel(a).android
    // if(0 != self->relandroid)
    // {
    //     xh_elf_packed_reloc_iterator_init(&packed_iter, self->relandroid, self->relandroid_sz, self->is_use_rela);
    //     while(NULL != (rel_common = xh_elf_packed_reloc_iterator_next(&packed_iter)))
    //     {
    //         if(0 != (r = xh_elf_find_and_replace_func(self,
    //                                                   (self->is_use_rela ? ".rela.android" : ".rel.android"), 0,
    //                                                   symbol, new_func, old_func,
    //                                                   symidx, rel_common, NULL))) return r;
    //     }
    // }

    return 0;
}

void hook(const char* lib_name, const char* symbol_name)
{
    char       line[512];
    FILE      *fp;
    uintptr_t  base_addr = 0;
    uintptr_t  addr;
    xh_core_map_info mi;
    printf("===== hook begin=====\n");

    // find base address of libtest.so
    if(NULL == (fp = fopen("/proc/self/maps", "r"))) return;
    while(fgets(line, sizeof(line), fp))
    {
        char                     perm[5];
        unsigned long            offset;
        int                      pathname_pos;
        char                    *pathname;
        printf("[debug] line %s", line);

        // if (NULL != strstr(line, "libtestso.so")){
        if (NULL != strstr(line, lib_name)){
            if (sscanf(line, "%" PRIxPTR"-%*lx %4s %lx %*x:%*x %*d%n", &base_addr, perm, &offset, &pathname_pos) !=3)
                continue;

            if (0 != offset)
                continue;

            printf("[debug] base_addr:%" PRIxPTR" offset:%x pathname_pos:%d\n", base_addr, offset, pathname_pos);

            //get pathname
            while(isspace(line[pathname_pos]) && pathname_pos < (int)(sizeof(line) - 1))
                pathname_pos += 1;
            if(pathname_pos >= (int)(sizeof(line) - 1)) continue;
            pathname = line + pathname_pos;

            printf("pathname: %s", pathname);

            //elf header
            ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base_addr;
            printf("ehdr->e_type %d\n", ehdr->e_type);

            mi.pathname = strdup(pathname);
            mi.base_addr = base_addr;

            //xh_elf_init
            int ret_init = xh_elf_init(&(mi.elf), mi.base_addr, mi.pathname);
            printf("ret_init %d\n", ret_init);
            xh_elf_t *self = &(mi.elf);


            //xh_elf_hook
            const char* symbol = symbol_name;
            void* new_fun = (void*)my_malloc;
            void* old_fun = NULL;
            xh_elf_hook(&(mi.elf), symbol, new_fun, &old_fun);
            break;
        }
    }


    fclose(fp);

    printf("=====end hook=====\n");

}

void direct_hook(){
    char       line[512];
    FILE      *fp;
    uintptr_t  base_addr = 0;
    uintptr_t  addr;
    xh_core_map_info mi;
    printf("=====direct_hook begin=====\n");

    // find base address of libtest.so
    if(NULL == (fp = fopen("/proc/self/maps", "r"))) return;
    while(fgets(line, sizeof(line), fp))
    {
        char                     perm[5];
        unsigned long            offset;
        int                      pathname_pos;
        char                    *pathname;
        printf("[debug] line %s", line);

        if (NULL != strstr(line, "libtestso.so")){
            if (sscanf(line, "%" PRIxPTR"-%*lx %4s %lx %*x:%*x %*d%n", &base_addr, perm, &offset, &pathname_pos) !=3)
                continue;

            break;
        }
    }

    fclose(fp);
    if(0 == base_addr) return;

    //the absolute address
    addr = base_addr + 0x000000201020;      //64
    // addr = base_addr + 0x00002010;          //32

    printf("base_addr:%" PRIxPTR", malloc addr:%" PRIxPTR"\n", base_addr, addr);

    printf("===============================================\n");
    //add write permission
    mprotect((void *)PAGE_START(addr), PAGE_COVER(addr), PROT_READ | PROT_WRITE);

    //replace the function address
    *(void **)addr = (void*)my_malloc;

    // mprotect((void *)PAGE_START(addr), PAGE_COVER(addr), PROT_READ | PROT_WRITE);

    //clear instruction cache
    __builtin___clear_cache((void *)PAGE_START(addr), (void *)PAGE_END(addr));

    printf("=====direct_hook end=====\n");
}

int main()
{
    hook("libtestso.so", "malloc");
    // hook("libstdc++.so", "malloc");

    // direct_hook();

    // printf("hello \n");
    sotest_malloc();
    return 0;
}