#include "moat/moat_pks.h"
#include "asm/pgtable.h"
#include "asm/pgtable_64_types.h"
#include "asm/pgtable_types.h"
#include "asm/tlbflush.h"

u64 get_asid(void) {
  return raw_cpu_read(cpu_tlbstate.loaded_mm_asid) + 1;
}

u64 get_bpf_pgd(void) {
  return raw_cpu_read(cpu_tlbstate.bpf_pgd);
}

void set_bpf_pgd(u64 new_pgd) {
  raw_cpu_write(cpu_tlbstate.bpf_pgd, new_pgd);
}

void set_bpf_mm(void) {
  raw_cpu_write(cpu_tlbstate.is_bpf_mm, 1);
}

void clr_bpf_mm(void) {
  raw_cpu_write(cpu_tlbstate.is_bpf_mm, 0);
}

bool get_bpf_mm(void) {
  return raw_cpu_read(cpu_tlbstate.is_bpf_mm);
}


static int prot_pkey(pgprot_t prot) {
  return (_PK_MASK & pgprot_val(prot)) >> _PAGE_BIT_PKEY_BIT0;
}

int pks_lookup_in_pgd(pgd_t *pgd, u64 addr, int *level) {
  pgprot_t prot;
  pte_t *ppte = lookup_address_in_pgd(pgd_offset_pgd(pgd, addr), addr, level); prot = pte_pgprot(*ppte);
  return prot_pkey(prot) ;
}

int pks_assign_in_pgd(pgd_t *pgd, u64 addr, int pkey)
{
	int level;
	pte_t *ppte = lookup_address_in_pgd(pgd_offset_pgd(pgd, addr), addr, &level);
	pte_t old_pte, new_pte;
	pgprot_t new_prot;
	u64 pfn;
  int ret;
	if (ppte == NULL) {
		pr_err("pte not found\n");
		return 0;
	}
	old_pte = *ppte;
  ret = prot_pkey(pte_pgprot(old_pte));
	pfn = pte_pfn(old_pte);
	new_prot = pte_pgprot(old_pte);
	pgprot_val(new_prot) &= ~_PAGE_PKEY(0xf);
	pgprot_val(new_prot) |= _PAGE_PKEY(pkey);
	
	new_pte = pfn_pte(pfn, new_prot);
	set_pte(ppte, new_pte);
  return ret;
}


EXPORT_SYMBOL(pks_lookup_in_pgd);
EXPORT_SYMBOL(pks_assign_in_pgd);
