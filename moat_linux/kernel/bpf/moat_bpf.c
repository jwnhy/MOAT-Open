#include "moat/moat_bpf.h"
#include "asm/desc.h"
#include "linux/container_of.h"
#include "linux/percpu-defs.h"
#include "moat/moat_pks.h"
#include "linux/filter.h"
#include "linux/mm.h"

u64 moat_sum;
atomic_t moat_count;
DEFINE_SPINLOCK(moat_lock);
EXPORT_SYMBOL(moat_sum);
EXPORT_SYMBOL(moat_count);
EXPORT_SYMBOL(moat_lock);

struct moat_vm moat_mm;
void *moat_scratch_page; // for fixing expected fault
static atomic_t pks_inited;
static atomic_t pcid;
DEFINE_PER_CPU(void*, last_bpf);
DEFINE_PER_CPU(u32, in_bpf); // initialized
DEFINE_PER_CPU(bool, moat_fault_expected) = false;
EXPORT_PER_CPU_SYMBOL(in_bpf); // initialized
EXPORT_PER_CPU_SYMBOL(moat_fault_expected);
EXPORT_PER_CPU_SYMBOL(last_bpf);

EXPORT_SYMBOL(init_mm);
EXPORT_SYMBOL(get_asid);
EXPORT_SYMBOL(set_bpf_pgd);
EXPORT_SYMBOL(get_bpf_pgd);
EXPORT_SYMBOL(set_bpf_mm);
EXPORT_SYMBOL(clr_bpf_mm);
EXPORT_SYMBOL(get_bpf_mm);

static p4d_t *moat_p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
				     unsigned long address)
{
	if (unlikely(pgd_none(*pgd))) {
		if (__p4d_alloc(mm, pgd, address))
			return NULL;
	}
  
	return p4d_offset(pgd, address);
}

static pud_t *moat_pud_alloc(struct mm_struct *mm, p4d_t *p4d,
				     unsigned long address)
{
	if (unlikely(p4d_none(*p4d))) {
		if (__pud_alloc(mm, p4d, address))
			return NULL;
	}
  return pud_offset(p4d, address);
}

static pmd_t *moat_pmd_alloc(struct mm_struct *mm, pud_t *pud,
				     unsigned long address)
{
	if (unlikely(pud_none(*pud))) {
		if (__pmd_alloc(mm, pud, address))
			return NULL;
	}

	return pmd_offset(pud, address);
}

#define moat_pte_alloc(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) &&					\
	  (__pte_alloc_kernel(pmd)))?\
		NULL: pte_offset_kernel(pmd, address))

static int vmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot)
{
	pte_t *pte;
	u64 pfn;
	unsigned long size = PAGE_SIZE;

	pfn = phys_addr >> PAGE_SHIFT;
	pte = moat_pte_alloc(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		BUG_ON(!pte_none(*pte));
		set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));
    //set_pte(pte, pfn_pte(pfn, prot));
		pfn++;
	} while (pte += PFN_DOWN(size), addr += size, addr != end);
	return 0;
}

static int vmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = moat_pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);

		if (vmap_pte_range(pmd, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (pmd++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

static int vmap_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	pud = moat_pud_alloc(&init_mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);

		if (vmap_pmd_range(pud, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (pud++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

static int vmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = moat_p4d_alloc(&init_mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);

		if (vmap_pud_range(p4d, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (p4d++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

int moat_vmap_range(unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot, pgd_t* pgd)
{
	unsigned long start;
	unsigned long next;
	int err;

	might_sleep();
	BUG_ON(addr >= end);

	start = addr;
  pgd = pgd_offset_pgd(pgd, addr);
	//pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = vmap_p4d_range(pgd, addr, next, phys_addr, prot);
		if (err)
			break;
	} while (pgd++, phys_addr += (next - addr), addr = next, addr != end);
	return err;
}


static void vunmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static void vunmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		vunmap_pte_range(pmd, addr, next);

		cond_resched();
	} while (pmd++, addr = next, addr != end);
}

static void vunmap_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		vunmap_pmd_range(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

static void vunmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		vunmap_pud_range(p4d, addr, next);
	} while (p4d++, addr = next, addr != end);
}

void moat_vunmap_range(unsigned long start, unsigned long end, pgd_t *pgd)
{
	unsigned long next;
	unsigned long addr = start;

  pgd = pgd_offset_pgd(pgd, addr);
	BUG_ON(addr >= end);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		vunmap_p4d_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

/* this function should only be called when holding moat_mm.lock!
 */
unsigned long alloc_virt_locked(unsigned long nr_pages) {
  unsigned long size, addr;

  size = nr_pages * PAGE_SIZE;
  addr = moat_mm.cur;
	moat_mm.cur += size;
	BUG_ON(moat_mm.cur >= MOAT_END);

  return addr;
}

// basically copy a moat_mem and (map?) it to a new virtual address
struct moat_mem *build_moat_mem(unsigned long addr, unsigned long nr_pages, pgprot_t prot) {
  struct moat_mem *new_mem;
  new_mem = kmalloc(sizeof(struct moat_mem), GFP_KERNEL);
  new_mem->addr = (void*)addr;
  new_mem->phys_pages = NULL;
  new_mem->nr_pages = nr_pages;
  new_mem->prot = __pgprot(pgprot_val(prot) | _PAGE_PKEY_BIT0);
  new_mem->shared = false;
  return new_mem;
}

// TODO: add fault checks
int alloc_map_moat_mem(struct moat_mem* mem, gfp_t gfp_extra_flags) {
	pgd_t *pgd;
  void* phys_start;
  pgprot_t prot;
  unsigned long addr, size;

  size = mem->nr_pages * PAGE_SIZE;
  prot = mem->prot;
  addr = (u64)mem->addr;
  if (mem->shared && !mem->phys_pages)
    return -ENOMEM;
  if (mem->shared)
    phys_start = mem->phys_pages;
  else
    phys_start = mem->phys_pages = alloc_pages_exact(size, GFP_KERNEL | __GFP_ZERO | gfp_extra_flags);
  pgd = init_mm.pgd;
  return moat_vmap_range(addr, addr+size, virt_to_phys(phys_start), prot, pgd);
}

struct moat_mem *alloc_moat_mem(unsigned long nr_pages, pgprot_t prot, gfp_t gfp_extra_flags)
{
  struct moat_mem* allocated;
	unsigned long addr, size; 
  int ret;

  size = nr_pages * PAGE_SIZE;

	spin_lock(
		&moat_mm.lock); // don't think we're gonna need call this in irq;
  addr = alloc_virt_locked(nr_pages);
	spin_unlock(&moat_mm.lock);
  // everything allocated through moat_mem should be key 1
  prot = __pgprot(pgprot_val(prot) | _PAGE_PKEY_BIT0);
  allocated = build_moat_mem(addr, nr_pages, prot);
  ret = alloc_map_moat_mem(allocated, gfp_extra_flags);
  if (ret) {
    kfree(allocated);
    return NULL;
  }
  return allocated;
}

void dealloc_moat_mem(struct moat_mem *allocated) {
  unsigned long size, addr;
  pgd_t *pgd;
  // return without free
  if (!allocated)
    return;

  size = allocated->nr_pages * PAGE_SIZE;
  addr = (unsigned long)allocated->addr;
  spin_lock(&moat_mm.lock);
  if (moat_mm.cur == addr + size)
    moat_mm.cur -= size;
  spin_unlock(&moat_mm.lock);

  pgd = init_mm.pgd;
  moat_vunmap_range(addr, addr + size, pgd);
  // if not shared, free physical pages
  if (!allocated->shared)
    free_pages_exact(allocated->phys_pages, size);
  kfree(allocated);
  
  // we *only* flush the tlb in kernel.
  //flush_tlb_kernel_range(addr, addr+size);
}

struct desc {
	unsigned short size;
	unsigned long base;
} __attribute__((packed));

void init_moat_mm(void)
{
  pgd_t *top_pgd, *pgd;
  p4d_t *p4d;
  unsigned long addr = MOAT_START;
  int nr_pgd, i, cpu, pkey, level;
  u64 jumptable;
  struct desc idt;

  __asm__ volatile("sidt %0" : "=m"(idt));
  pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)idt.base, &level);
  printk("[MOAT]: Before idt %llx, pkey: %d, level: %d;\n", (u64)idt.base, pkey, level);
  pks_assign_in_pgd(init_mm.pgd, (u64)idt.base, 0x2);
  pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)idt.base, &level);
  printk("[MOAT]: After idt %llx, pkey: %d, level: %d;\n", (u64)idt.base, pkey, level);

  for_each_possible_cpu(cpu) {
    pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)get_cpu_gdt_ro(cpu), &level);
    printk("[MOAT]: Before gdt %llx, pkey: %d, level: %d;\n", (u64)get_cpu_gdt_ro(cpu), pkey, level);
		pks_assign_in_pgd(init_mm.pgd, (u64)get_cpu_gdt_ro(cpu), 0x2);
    pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)get_cpu_gdt_ro(cpu), &level);
    printk("[MOAT]: After gdt %llx, pkey: %d, level: %d;\n", (u64)get_cpu_gdt_ro(cpu), pkey, level);

    pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)per_cpu_ptr(&in_bpf, cpu), &level);
    printk("[MOAT]: Before in_bpf %llx, pkey: %d, level: %d;\n", (u64)per_cpu_ptr(&in_bpf, cpu), pkey, level);
		pks_assign_in_pgd(init_mm.pgd, (u64)per_cpu_ptr(&in_bpf, cpu), 0x2);
    pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)per_cpu_ptr(&in_bpf, cpu), &level);
    printk("[MOAT]: After in_bpf %llx, pkey: %d, level: %d;\n", (u64)per_cpu_ptr(&in_bpf, cpu), pkey, level);
    
    *per_cpu_ptr(&in_bpf, cpu) = false;
  }

  /* Only for interpreter */ 
  jumptable = moat_lookup_name("jumptable");
  pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)jumptable, &level);
  printk("[MOAT]: Before jumptable %llx, pkey: %d, level: %d;\n", (u64)jumptable, pkey, level);
  pks_assign_in_pgd(init_mm.pgd, (u64)jumptable, 0x2);
  pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)jumptable, &level);
  printk("[MOAT]: After jumptable %llx, pkey: %d, level: %d;\n", (u64)jumptable, pkey, level);

  pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)__bpf_call_base, &level);
  printk("[MOAT]: Before __bpf_call_base %llx, pkey: %d, level: %d;\n", (u64)__bpf_call_base, pkey, level);
  pks_assign_in_pgd(init_mm.pgd, (u64)__bpf_call_base, 0x2);
  pkey = pks_lookup_in_pgd(init_mm.pgd, (u64)__bpf_call_base, &level);
  printk("[MOAT]: After __bpf_call_base %llx, pkey: %d, level: %d;\n", (u64)__bpf_call_base, pkey, level);

  pks_assign_in_pgd(init_mm.pgd, __this_cpu_ist_top_va(DF), 0x2);
  pks_assign_in_pgd(init_mm.pgd, __this_cpu_ist_top_va(DB), 0x2);
  pks_assign_in_pgd(init_mm.pgd, __this_cpu_ist_top_va(NMI), 0x2);

	spin_lock_init(&moat_mm.lock);
	moat_mm.cur = MOAT_START;

  init_mm.moat_pgd = init_mm.pgd + pgd_index(MOAT_START);
  /* Testing */
  moat_scratch_page = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL);

  top_pgd = init_mm.pgd;
  pgd = pgd_offset_pgd(top_pgd, addr);
  p4d = p4d_offset(pgd, addr);

  /* We assume 4 page level, pgd = p4d*/
  BUG_ON(p4d != (p4d_t *)pgd);
  nr_pgd = (MOAT_END - MOAT_START) >> 39;
  for (i = 0; i < nr_pgd; i++) {
    BUG_ON(!moat_pud_alloc(&init_mm, p4d, addr));
    addr = pgd_addr_end(addr, MOAT_END);
    pgd = pgd_offset_pgd(top_pgd, addr);
    // dummy transition.
    p4d = p4d_offset(pgd, addr);
  }
}

struct moat_addrspace* alloc_moat_addrspace(void) {
  struct moat_addrspace *addrspace;
  pgd_t *pgd;
  int i;
  addrspace = kmalloc(sizeof(struct moat_addrspace), GFP_KERNEL);
  pgd = alloc_pages_exact(PAGE_SIZE, GFP_PGTABLE_KERNEL);
  memcpy(pgd, init_mm.pgd, PTRS_PER_PGD * sizeof(pgd_t));
  for (i = pgd_index(MOAT_START); i < pgd_index(MOAT_END); i++) {
    // invalidate BPF domain, use `addto_moat_addrspace` to reassign
    (*(pgd+i)).pgd = 0;
  }

  addrspace->pgd = pgd;
  addrspace->moat_pgd = addrspace->pgd + pgd_index(MOAT_START);
  addrspace->init_moat_pgd = init_mm.pgd + pgd_index(MOAT_START);
  INIT_LIST_HEAD(&addrspace->region_list);
  return addrspace;
}

void dealloc_moat_addrspace(struct moat_addrspace* addrspace) {
  struct list_head *entry, *temp;
  list_for_each_safe(entry, temp, &addrspace->region_list) {
    struct moat_region* region;
    region = list_entry(entry, struct moat_region, entry);
    list_del(entry);
    kfree(region);
  }
  free_pages_exact(addrspace->pgd, PAGE_SIZE);
  kfree(addrspace);
}

int addto_moat_addrspace(struct moat_addrspace* addrspace, struct moat_mem *mem, char *name) {
  unsigned long start, end;
  pgprot_t prot;
  pgd_t *pgd;
  struct moat_region* region;

  region = kmalloc(sizeof(struct moat_region), GFP_KERNEL);
  region->mem = mem;
  list_add(&region->entry, &addrspace->region_list);

  start = (unsigned long)mem->addr;
  end = start + mem->nr_pages * PAGE_SIZE;
  prot = mem->prot;
  //if (!(pgprot_val(prot) & _PAGE_PKEY_BIT0)) {
  //  printk("[MOAT] set pkey = 0x1 for BPF domain");
  // Remove Global bits in these pages, so they can be flushed when BPF changes
  prot = __pgprot(pgprot_val(prot) | _PAGE_PKEY_BIT0 & ~_PAGE_GLOBAL);
  //}
  pgd = addrspace->pgd;
  strcpy(region->name, name);
  return moat_vmap_range(start, end, virt_to_phys(mem->phys_pages), prot, pgd);
}

void delfrom_moat_addrspace(struct moat_addrspace* addrspace, struct moat_mem *mem) {
  unsigned long start, end;
  pgd_t *pgd;

  struct list_head *entry, *temp;
  list_for_each_safe(entry, temp, &addrspace->region_list) {
    struct moat_region* region;
    region = list_entry(entry, struct moat_region, entry);
    if (region->mem == mem) {
      list_del(entry);
      kfree(region);
    }
  }

  start = (unsigned long)mem->addr;
  end = start + mem->nr_pages * PAGE_SIZE;
  pgd = addrspace->pgd;

  moat_vunmap_range(start, end, pgd);
}

void list_moat_regions_local(struct moat_addrspace* addrspace) {
  struct list_head *entry;
  unsigned long start, end;
  printk("[MOAT] list regions of addrspace @ %lx\n", (unsigned long)addrspace);
  list_for_each(entry, &addrspace->region_list) {
    struct moat_region* region;
    int level, pkey;
    region = list_entry(entry, struct moat_region, entry);
    start = (unsigned long) region->mem->addr;
    end = start + region->mem->nr_pages * PAGE_SIZE;
    pkey = pks_lookup_in_pgd(addrspace->pgd, start, &level);
    printk("\tRegion %s: [%lx ~ %lx] with pkey=%d\n", region->name, start, end, pkey);   
  }
}


void list_moat_regions(struct moat_addrspace* addrspace) {
  struct list_head *entry;
  unsigned long start, end;
  printk("[MOAT] list regions of addrspace @ %lx\n", (unsigned long)addrspace);
  list_for_each(entry, &addrspace->region_list) {
    struct moat_region* region;
    pgd_t *pgd;
    int level, pkey;
    region = list_entry(entry, struct moat_region, entry);
    start = (unsigned long) region->mem->addr;
    end = start + region->mem->nr_pages * PAGE_SIZE;
    pgd = __va(read_cr3_pa());
    pkey = pks_lookup_in_pgd(pgd, start, &level);
    printk("\tRegion %s: [%lx ~ %lx] with pkey=%d\n", region->name, start, end, pkey);   
  }
}

void __always_inline switch_moat_addrspace(pgd_t *pgd, struct moat_addrspace* addrspace) {
  pgd->pgd = addrspace->moat_pgd->pgd;
  //load_cr3(addrspace->pgd);
  //flush_tlb_kernel_range(MOAT_START, MOAT_END);
}

void __always_inline switch_back_addrspace(pgd_t* pgd) {
  pgd->pgd = init_mm.moat_pgd->pgd;
  //load_cr3(pgd);
}

static enum bpf_map_type supported_maps[] = {
  BPF_MAP_TYPE_ARRAY,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_PERCPU_ARRAY,
  BPF_MAP_TYPE_PERCPU_HASH,
  BPF_MAP_TYPE_LRU_PERCPU_HASH,
  BPF_MAP_TYPE_LRU_HASH,
  BPF_MAP_TYPE_RINGBUF,
};

static int is_map_supported(enum bpf_map_type typ) {
  int j;
  int max_j = sizeof(supported_maps) / sizeof(enum bpf_map_type);
  for (j = 0; j < max_j; j++) {
    if (typ == supported_maps[j])
      return true;
  }
  return false;
}

void prepare_moat_prog(struct bpf_prog *prog, gfp_t gfp_extra_flags) {
  struct moat_addrspace *addrspace;
  struct bpf_map **used_maps, *map;
  int i, used_map_cnt;
  int cpu, nr_pages, prog_size;
  void *prog_src;
  gfp_t gfp_flags;
  pgprot_t stack_prot, prog_prot;

  addrspace = alloc_moat_addrspace();
  gfp_flags = GFP_KERNEL | __GFP_ZERO | gfp_extra_flags;

  prog->pack.pcid = (6 + atomic_inc_return(&pcid)) % 4096;
  /* alloc stack memory */
  prog->stacks = alloc_percpu_gfp(struct moat_mem*, gfp_flags);
  prog->bpf_stacks = alloc_percpu_gfp(struct moat_mem*, gfp_flags);
  prog->pack.percpu_stack = alloc_percpu_gfp(u64, gfp_flags);
  prog->pack.percpu_bpf_stack = alloc_percpu_gfp(u64, gfp_flags);
  prog->pack.percpu_ctx = alloc_percpu_gfp(u64, gfp_flags);
  prog->pack.ctx_ppte = alloc_percpu_gfp(pte_t*, gfp_flags);
  prog->cpu_stack_cnt = alloc_percpu_gfp(atomic_t, gfp_flags); 

  for_each_possible_cpu(cpu) {
    struct moat_mem **percpu_stack_mem;
    struct moat_mem *percpu_ctx_mem;
    pte_t *ppte;
    u64 *percpu_stack;
    u64 ctx_virt;
    int level;
    percpu_stack_mem = per_cpu_ptr(prog->stacks, cpu);
    stack_prot = PAGE_KERNEL;
    stack_prot = __pgprot(pgprot_val(stack_prot) | _PAGE_PKEY_BIT0);
    *percpu_stack_mem = alloc_moat_mem(PAGE_FOR_STACK, stack_prot, gfp_flags);
    addto_moat_addrspace(addrspace, *percpu_stack_mem, "stack");

    percpu_stack = per_cpu_ptr(prog->pack.percpu_stack, cpu);
    *percpu_stack = (u64)(*percpu_stack_mem)->addr + PAGE_FOR_STACK * PAGE_SIZE - ((prog->pack.pcid % 56) * 64);

    /*
    spin_lock(&moat_mm.lock);
    ctx_virt = alloc_virt_locked(2);
    spin_unlock(&moat_mm.lock);
    percpu_ctx_mem = build_moat_mem(ctx_virt, 2, stack_prot);
    addto_moat_addrspace(addrspace, percpu_ctx_mem, "ctx_no");
    *per_cpu_ptr(prog->pack.percpu_ctx, cpu) = (u64)percpu_ctx_mem->addr;
    ppte = lookup_address_in_pgd(addrspace->moat_pgd, (unsigned long)percpu_ctx_mem->addr, &level);
    if (ppte == NULL)
      printk("[MOAT] ppte not found!\n");
    *per_cpu_ptr(prog->pack.ctx_ppte, cpu) = ppte;
    */
    /* additional stack is required for non-jited code */
    if (!prog->jited) {
      percpu_stack_mem = per_cpu_ptr(prog->bpf_stacks, cpu);
      *percpu_stack_mem = alloc_moat_mem(PAGE_FOR_STACK, stack_prot, gfp_flags);
      addto_moat_addrspace(addrspace, *percpu_stack_mem, "int_stack");

      percpu_stack = per_cpu_ptr(prog->pack.percpu_bpf_stack, cpu);
      *percpu_stack = (u64)(*percpu_stack_mem)->addr + PAGE_FOR_STACK * PAGE_SIZE - ((prog->pack.pcid % 56) * 64);
    }
  }
  
  /* allocate program memory */
  if (!prog->jited) {
    nr_pages = round_up(prog->len * sizeof(struct bpf_insn), PAGE_SIZE) / PAGE_SIZE;
    prog_prot = PAGE_KERNEL;
    prog_prot = __pgprot(pgprot_val(prog_prot) | _PAGE_PKEY_BIT0);
    prog_src = (void*)prog->insnsi;
    prog_size = prog->len * sizeof(struct bpf_insn);
    prog->prog_mem = alloc_moat_mem(nr_pages, prog_prot, gfp_flags);
    /* COPY TO ADDR NOT MEM */
    memcpy(prog->prog_mem->addr, prog_src, prog_size);
    addto_moat_addrspace(addrspace, prog->prog_mem, "prog");
  }
  /* add map memory */
  /* TODO: let's worry about maps later */
  used_maps = prog->aux->used_maps;
  used_map_cnt = prog->aux->used_map_cnt;
  for (i = 0; i < used_map_cnt; i++) {
    struct list_head *entry;
    map = used_maps[i];
    if (!is_map_supported(map->map_type))
      BUG();
    list_for_each(entry, &map->region_list) {
      struct moat_region* region;
      region = list_entry(entry, struct moat_region, entry);
      // printk("[MOAT] prepare map %llx @ %llx\n", (u64)region->mem->addr, (u64)region->mem);
      addto_moat_addrspace(addrspace, region->mem, "map");
    }
  }
  list_moat_regions_local(addrspace);
  prog->addrspace = addrspace;
  
  prog->pack.init_pgd_val = *(init_mm.pgd + pgd_index(MOAT_START));
  prog->pack.moat_pgd_val = *(addrspace->pgd + pgd_index(MOAT_START));
  prog->pack.addrspace_pgd = addrspace->pgd;
  addrspace->pgd->pgd = addrspace->pgd->pgd | (1ULL << 63);

  if (atomic_xchg(&pks_inited, 1) == 0)
    on_each_cpu(pks_init, NULL, 0);
}

int moat_mem_mmap(struct vm_area_struct* vma, struct moat_mem* mem, unsigned long pgoff) {
  unsigned long uaddr = vma->vm_start;
  unsigned long size = vma->vm_end - uaddr;
  unsigned long off, end_index;
  void* kaddr = mem->addr;

  if (check_shl_overflow(pgoff, PAGE_SHIFT, &off))
    return -EINVAL;
  size = PAGE_ALIGN(size);
  if(!PAGE_ALIGNED(uaddr) || !PAGE_ALIGNED(kaddr))
    return -EINVAL;
  if (check_add_overflow(size, off, &end_index) || end_index > (u64)kaddr + mem->nr_pages * PAGE_SIZE)
    return -EINVAL;
  kaddr += off;

  do {
    pte_t *kpte;
    int level, ret;
    struct page* page;
    kpte = lookup_address((u64)kaddr, &level);
    if (!kpte)
      return -EINVAL;
    page = pte_page(*kpte);
    ret = vm_insert_page(vma, uaddr, page);
    if (ret)
      printk("[MOAT] mmap fault %d\n", ret);

    uaddr += PAGE_SIZE;
    kaddr += PAGE_SIZE;
    size -= PAGE_SIZE;
  } while (size > 0);
  return 0;
}

struct moat_obj_mem* build_moat_obj_mem(unsigned long addr, unsigned long nr_pages, unsigned int obj_size, pgprot_t prot) {
  struct moat_obj_mem *obj_mem;
  struct moat_mem *mem;
  int cpu;


  obj_mem = kmalloc(sizeof(struct moat_obj_mem), GFP_KERNEL);
  obj_mem->obj_size = offsetof(struct moat_obj, data) + obj_size;
  obj_mem->total_obj = nr_pages * PAGE_SIZE / obj_mem->obj_size;
  obj_mem->avail_obj = obj_mem->total_obj;

  spin_lock_init(&obj_mem->lock);
  obj_mem->pcpu_free_list = alloc_percpu(struct list_head);
  obj_mem->pcpu_obj = alloc_percpu(unsigned int);
  INIT_LIST_HEAD(&obj_mem->free_list);
  for_each_possible_cpu(cpu) {
    INIT_LIST_HEAD(per_cpu_ptr(obj_mem->pcpu_free_list, cpu));
    *per_cpu_ptr(obj_mem->pcpu_obj, cpu) = 0;
  }

  mem = &obj_mem->mem;
  mem->addr = (void*)addr;
  mem->phys_pages = NULL;
  mem->nr_pages = nr_pages;
  mem->prot = prot;
  mem->shared = false;
  return obj_mem;
}

struct moat_obj_mem* alloc_moat_obj_mem(unsigned long nr_pages, unsigned int obj_size, pgprot_t prot, gfp_t flags) {
  u64 addr;
  struct moat_obj *obj;
  int i;
  struct moat_obj_mem* obj_mem;
  spin_lock(&moat_mm.lock);
  addr = alloc_virt_locked(nr_pages);
  spin_unlock(&moat_mm.lock);
  obj_mem = build_moat_obj_mem(addr, nr_pages, obj_size, prot);
  alloc_map_moat_mem(&obj_mem->mem, flags);

  // populate free list
  for (i = 0; i < obj_mem->total_obj; i++) {
    obj = (struct moat_obj*) addr;
    obj->mem = obj_mem;
    list_add(&obj->entry, &obj_mem->free_list);
    addr += obj_mem->obj_size;
  }
  return obj_mem;
}

void* alloc_moat_obj(struct moat_obj_mem *obj_mem) {
  unsigned int *pcpu_obj = this_cpu_ptr(obj_mem->pcpu_obj);
  struct moat_obj *ret_obj;
  if (*pcpu_obj > 0) {
    struct list_head * pcpu_free_list= this_cpu_ptr(obj_mem->pcpu_free_list);
    *pcpu_obj -= 1;
    ret_obj = list_first_entry_or_null(pcpu_free_list, struct moat_obj, entry);
    if (!ret_obj)
      BUG();
    list_del(&ret_obj->entry);
    return ret_obj->data;
  }
  spin_lock(&obj_mem->lock);
  obj_mem->avail_obj -= 1;
  ret_obj = list_first_entry_or_null(&obj_mem->free_list, struct moat_obj, entry);
  if (!ret_obj)
    BUG();
  list_del(&ret_obj->entry);
  spin_unlock(&obj_mem->lock);
  return ret_obj->data;
}

void dealloc_moat_obj(void* data) {
  struct moat_obj *obj = container_of(data, struct moat_obj, data);
  struct moat_obj_mem *obj_mem = obj->mem;
  unsigned int *pcpu_obj = this_cpu_ptr(obj_mem->pcpu_obj);
  if (*pcpu_obj < PCPU_OBJ_MAX) {
    struct list_head *pcpu_free_list = this_cpu_ptr(obj_mem->pcpu_free_list);
    *pcpu_obj += 1;
    list_add(&obj->entry, pcpu_free_list);
  }
  spin_lock(&obj_mem->lock);
  obj_mem->avail_obj += 1;
  list_add(&obj->entry, &obj_mem->free_list);
  spin_unlock(&obj_mem->lock);
}

void dealloc_moat_obj_mem(struct moat_obj_mem* obj_mem) {
  dealloc_moat_mem(&obj_mem->mem);
}

EXPORT_SYMBOL(alloc_moat_addrspace);
EXPORT_SYMBOL(dealloc_moat_addrspace);

EXPORT_SYMBOL(addto_moat_addrspace);
EXPORT_SYMBOL(delfrom_moat_addrspace);
EXPORT_SYMBOL(switch_moat_addrspace);
EXPORT_SYMBOL(switch_back_addrspace);
EXPORT_SYMBOL(list_moat_regions);
EXPORT_SYMBOL(list_moat_regions_local);

EXPORT_SYMBOL(alloc_moat_mem);
EXPORT_SYMBOL(dealloc_moat_mem);

EXPORT_SYMBOL(moat_vmap_range);
EXPORT_SYMBOL(moat_vunmap_range);

EXPORT_SYMBOL(init_moat_mm);
