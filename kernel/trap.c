#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[], userret[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

// https://stackoverflow.com/a/27627015/6680182
void print_binary(uint32 number, int length) {
  if (length) {
    print_binary(number >> 1, length - 1);
    printf("%s", (number & 1) ? "1" : "0");
    if (length % 4 == 0) {
      printf(" ");
    }
  }
}

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
  int which_dev = 0;

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec);

  struct proc *p = myproc();
  
  // save user program counter.
  p->tf->epc = r_sepc();
  
  if(r_scause() == 8){
    // system call

    if(p->killed)
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->tf->epc += 4;

    // an interrupt will change sstatus &c registers,
    // so don't enable until done with those registers.
    intr_on();

    syscall();
  } else if(p->guest) {

    // printf("%p\n", r_sepc());
    uint64 instr = 0;
    copyin(p->pagetable, (char*)&instr, r_sepc(), 4);
    uint64 opcode = instr & 0x7f;

    // print_binary(instr, 64); printf("\n");

    if (r_scause() == 2) {
      // illegal instruction

      if (instr == 0x30200073) {
        p->tf->epc = p->tf->mepc;
        goto dontAdvance;

      } else if (opcode == 0x73) {
        // csr instruction
        uint64 func3 = (instr >> 12) & 0x7;

        // get register number
        uint64 regInd = ((instr >> 7) & 0x1f);
        uint64* regPtr = (&p->tf->ra + regInd - 1);
        uint64 csr = (instr >> 20);

        // csrr
        if(func3 == 0x2){
          uint64 storeVal;

          if (csr == 0xf14) { // mhartid
            storeVal = 0;

          } else if (csr == 0x300) { // mstatus
            storeVal = 0; // may need to change
            // for now just set to zero (default during normal xv6 boot)

          } else if (csr == 0x304) { // mie
            storeVal = 0; // may need to change
            // for now just set to zero (default during normal xv6 boot)

          } else {
            printf("%s\n", "csrr");
            goto vmPanic;
          }

          // tf starts storing at x1 (ra), so -1 from index
          *regPtr = storeVal;

        // csrw
        } else if(func3 == 0x1){
          
          if (csr == 0x300) { // mstatus
            p->tf->mstatus = *regPtr;

          } else if (csr == 0x302) { // medeleg
            p->tf->medeleg = *regPtr;

          } else if (csr == 0x303) { // mideleg
            p->tf->mideleg = *regPtr;

          } else if (csr == 0x341) { // mepc
            p->tf->mepc = *regPtr;

          } else if (csr == 0x180) { // satp
            p->tf->kernel_satp = *regPtr;

          } else if (csr == 0x340) { // mscratch
            p->tf->mscratch = *regPtr;

          } else if (csr == 0x304) { // mie
           // enable machine-mode timer interrupts.
            p->tf->mie = *regPtr;

          } else if (csr == 0x305) { // mtvec
            // set the machine-mode trap handler.
            p->tf->mtvec = *regPtr;

          } else {
            printf("%s\n", "csrw");
            goto vmPanic;
          }

        } else {
          goto vmPanic;
        }
      }
    }

    else if(r_scause() == 0xd) { // guest load page fault
      uint64 va = r_stval();
      // guest tries to read cycles since boot
      if (va == 0x000000000200bff8) {
        // return garbage
      } else {
        goto vmPanic;
      }

    } else if(r_scause() == 0xf) { // guest store page fault
      uint64 va = r_stval();
      // guest tries to ask the CLINT for a timer interrupt.for hartid 0
      if (va == 0x0000000002004000) {
        // ignore
      } else {
        goto vmPanic;
      }

    } else {
      vmPanic:
      printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
      printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
      panic("vm trap");
    }

    // short instruction
    if ((instr & 0x3) != 0x3) {
      p->tf->epc += 2;
    } else {
      p->tf->epc += 4;
    }

    dontAdvance: ;
    
  } else if((which_dev = devintr()) != 0){
    // ok
  } else {
    printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
    printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
    p->killed = 1;
  }

  if(p->killed)
    exit(-1);

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2)
    yield();

  usertrapret();
}

//
// return to user space
//
void
usertrapret(void)
{
  struct proc *p = myproc();

  // turn off interrupts, since we're switching
  // now from kerneltrap() to usertrap().
  intr_off();

  // send syscalls, interrupts, and exceptions to trampoline.S
  w_stvec(TRAMPOLINE + (uservec - trampoline));

  // set up trapframe values that uservec will need when
  // the process next re-enters the kernel.
  p->tf->kernel_satp = r_satp();         // kernel page table
  p->tf->kernel_sp = p->kstack + PGSIZE; // process's kernel stack
  p->tf->kernel_trap = (uint64)usertrap;
  p->tf->kernel_hartid = r_tp();         // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.
  
  // set S Previous Privilege mode to User.
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  w_sepc(p->tf->epc);

  // tell trampoline.S the user page table to switch to.
  uint64 satp = MAKE_SATP(p->pagetable);

  // jump to trampoline.S at the top of memory, which 
  // switches to the user page table, restores user registers,
  // and switches to user mode with sret.
  uint64 fn = TRAMPOLINE + (userret - trampoline);
  ((void (*)(uint64,uint64))fn)(TRAPFRAME, satp);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
// must be 4-byte aligned to fit in stvec.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    printf("scause %p\n", scause);
    printf("sepc=%p stval=%p\n", r_sepc(), r_stval());
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2 && myproc() != 0 && myproc()->state == RUNNING)
    yield();

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  acquire(&tickslock);
  ticks++;
  wakeup(&ticks);
  release(&tickslock);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
  uint64 scause = r_scause();

  if((scause & 0x8000000000000000L) &&
     (scause & 0xff) == 9){
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ || irq == VIRTIO1_IRQ ){
      virtio_disk_intr(irq - VIRTIO0_IRQ);
    }

    plic_complete(irq);
    return 1;
  } else if(scause == 0x8000000000000001L){
    // software interrupt from a machine-mode timer interrupt,
    // forwarded by timervec in kernelvec.S.

    if(cpuid() == 0){
      clockintr();
    }
    
    // acknowledge the software interrupt by clearing
    // the SSIP bit in sip.
    w_sip(r_sip() & ~2);

    return 2;
  } else {
    return 0;
  }
}

