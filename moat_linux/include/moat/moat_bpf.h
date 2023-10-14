#ifndef __MOAT_BPF_H__
#define __MOAT_BPF_H__
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/bpf.h>
#include <asm/pgtable_types.h>
#include "asm-generic/cacheflush.h"
#include "asm/tlbflush.h"
#include "asm-generic/pgalloc.h"
#include "asm/pgtable_types.h"
#include "linux/list.h"
#include "linux/math.h"

/* 2 TiB VM, more than sufficient */
#define MOAT_START 0xffffe90000000000
#define MOAT_END   0xffffea0000000000

#define PAGE_FOR_STACK 1

DECLARE_PER_CPU(bool, moat_fault_expected);
DECLARE_PER_CPU(u32, in_bpf);
DECLARE_PER_CPU(void*, last_bpf);

// shared means this memory is used in MULTIPLE places;
// when deallocating, we only deallocate the original copy;
struct moat_mem {
  void *addr;
  void *phys_pages; 
  unsigned long nr_pages; 
  // used by alloc_map_moat_mem to avoid repeative allocation
  bool shared;
  pgprot_t prot;
  /* no refcnt; remember to dealloc them */
};

#define PCPU_OBJ_MAX 10
struct moat_obj_mem {
  struct moat_mem mem;
  spinlock_t lock;
  unsigned int total_obj;
  unsigned int avail_obj;
  unsigned int obj_size;
  struct list_head free_list;
  struct list_head __percpu *pcpu_free_list;
  unsigned int __percpu *pcpu_obj;
};

struct moat_obj {
  struct moat_obj_mem *mem; // who it belongs
  struct list_head entry;
  u8 data[];
};

struct moat_vm {
  spinlock_t lock;
  unsigned long cur; // within [MOAT_START, MOAT_END), increased in 4K granularity.
};
extern struct moat_vm moat_mm;

// one moat_mem may be referenced by different addrspace, we need this
// for 2-layer index.
struct moat_region {
  struct moat_mem *mem;
  struct list_head entry;
  int id;
  char name[10];
};

struct moat_addrspace {
  pgd_t *moat_pgd;
  pgd_t *init_moat_pgd;
  pgd_t *pgd;
  /* region list */
  struct list_head region_list;
};

extern void *moat_scratch_page; // for fixing expected fault

extern void init_moat_mm(void);

extern int moat_vmap_range(unsigned long addr, unsigned long end, phys_addr_t phys_addr, pgprot_t prot, pgd_t* pgd);
extern void moat_vunmap_range(unsigned long start, unsigned long end, pgd_t *pgd);

extern struct moat_mem *build_moat_mem(unsigned long addr, unsigned long nr_pages, pgprot_t prot);
extern unsigned long alloc_virt_locked(unsigned long nr_pages);
extern int alloc_map_moat_mem(struct moat_mem* mem, gfp_t gfp_extra_flags);

extern struct moat_mem * alloc_moat_mem(unsigned long, pgprot_t, gfp_t);
extern void dealloc_moat_mem(struct moat_mem *);
extern int moat_mem_mmap(struct vm_area_struct* vma, struct moat_mem* mem, unsigned long pgoff);

extern struct moat_addrspace* alloc_moat_addrspace(void);
extern void dealloc_moat_addrspace(struct moat_addrspace*);
extern int addto_moat_addrspace(struct moat_addrspace* addrspace, struct moat_mem *mem, char *name);
extern void delfrom_moat_addrspace(struct moat_addrspace* addrspace, struct moat_mem *mem);
extern void switch_moat_addrspace(pgd_t *pgd, struct moat_addrspace* addrspace);
extern void switch_back_addrspace(pgd_t *pgd);
extern void prepare_moat_prog(struct bpf_prog *prog, gfp_t gfp_extra_flags);

extern struct moat_obj_mem *alloc_moat_obj_mem(unsigned long nr_pages, unsigned int obj_size, pgprot_t, gfp_t);
extern struct moat_obj_mem *build_moat_obj_mem(unsigned long addr, unsigned long nr_pages, unsigned int obj_size, pgprot_t);
extern void dealloc_moat_obj_mem(struct moat_obj_mem*);
extern void* alloc_moat_obj(struct moat_obj_mem*);
extern void dealloc_moat_obj(void*);


extern void list_moat_regions(struct moat_addrspace* addrspace);
extern void list_moat_regions_local(struct moat_addrspace* addrspace);
#endif
