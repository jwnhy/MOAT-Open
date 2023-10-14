#ifndef __MOAT_PKS_H__
#define __MOAT_PKS_H__
#include "asm-generic/int-ll64.h"
#include "asm/msr.h"
#include "asm/pgtable_types.h"
#include "asm/tlbflush.h"

#define _PAGE_PKEY(pkey) (_AT(pteval_t, pkey) << _PAGE_BIT_PKEY_BIT0)
#define _PK_MASK (_AT(pteval_t, 0xF) << _PAGE_BIT_PKEY_BIT0)

#define MSR_IA32_PKRS 0x000006e1
#define X86_CR4_PKS_BIT 24
#define X86_CR4_PKS     _BITUL(X86_CR4_PKS_BIT)
#define PKR_BITS_PER_PKEY 2
#define PKEY_DISABLE_ACCESS	0x1
#define PKEY_DISABLE_WRITE	0x2
#define PKEY_ENABLE_ALL     0x0
#define PKR_AD_BIT 0x1u
#define PKR_WD_BIT 0x2u
#define KERNEL_PKRS 0x0
#define BPF_PKRS 0x1

int pks_lookup_in_pgd(pgd_t *pgd, u64 addr, int *level);
int pks_assign_in_pgd(pgd_t *pgd, u64 addr, int pkey);
u64 get_asid(void);
u64 get_bpf_pgd(void);
void set_bpf_pgd(u64 new_pgd);
void set_bpf_mm(void);
void clr_bpf_mm(void);
bool get_bpf_mm(void);


static void __always_inline pks_enable(void) {
	__asm__ volatile("mfence" ::: "memory");
	cr4_set_bits(X86_CR4_PKS);
	__asm__ volatile("mfence" ::: "memory");
}

static void __always_inline pks_disable(void)
{
	__asm__ volatile("mfence" ::: "memory");
	cr4_clear_bits(X86_CR4_PKS);
	__asm__ volatile("mfence" ::: "memory");
}

static void __always_inline notrace moat_write_msr(unsigned int msr, u64 val) {
	u32 low = (val & 0xffffffffULL), high = (val >> 32);
	asm volatile("1: wrmsr\n"
		     "2:\n" _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_WRMSR)
		     :
		     : "c"(msr), "a"(low), "d"(high)
		     : "memory");
}

static void __always_inline moat_write_pkrs(u32 new_pkrs)
{
  __asm__ volatile("mfence":::"memory");
	moat_write_msr(MSR_IA32_PKRS, new_pkrs);
  __asm__ volatile("mfence":::"memory");
}

static void __always_inline pks_init(void* info) {
  migrate_disable();
  moat_write_pkrs(0x0);
  pks_enable();
  printk("[MOAT] CR4 & PKRS Setup @ CPU %d CR4: %lx\n", raw_smp_processor_id(), native_read_cr4());
  migrate_enable();
}


#define rdtscp_begin(high, low) {\
  asm volatile ("cpuid\n\t"\
                "rdtscp\n\t"\
                "mov %%rdx, %0\n\t"\
                "mov %%rax, %1\n\t"\
                : "=r"(high), "=r"(low) \
                :\
                :"%rax","%rdx","%rcx","%rbx");\
}

#define rdtscp_end(high, low) {\
  asm volatile ("rdtscp\n\t"\
                "mov %%rdx, %0\n\t"\
                "mov %%rax, %1\n\t"\
                "cpuid\n\t"\
                : "=r"(high), "=r"(low) \
                :\
                :"%rax","%rdx","%rcx","%rbx");\
}


#endif
