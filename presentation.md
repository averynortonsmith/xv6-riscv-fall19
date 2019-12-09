
- trap-and-emulate and memory translation
- most of our work was done in trap.c
- added 'guest' field to proc struct
- wanted to maintain backwards compatibility for normal user programs
- priviledged instructions, hardware interaction, virtual memory, interrupts

----------

- take snapshot of kernel binary
- head to deal with size issue, symbol stripper
- load as user program

```
xv6 kernel is booting

virtio disk init 0
hart 2 starting
hart 1 starting
init: starting sh
$ ls
.              1 1 1024
..             1 1 1024
README         2 2 1982
xargstest.sh   2 3 93
cat            2 4 24224
echo           2 5 23072
forktest       2 6 13432
grep           2 7 27576
init           2 8 23808
kill           2 9 23048
ln             2 10 22984
ls             2 11 26464
mkdir          2 12 23144
rm             2 13 23128
sh             2 14 42016
stressfs       2 15 24136
usertests      2 16 123152
wc             2 17 25376
zombie         2 18 22536
cowtest        2 19 30576
uthread        2 20 28496
call           2 21 23080
testsh         2 22 40952
kalloctest     2 23 28120
bcachetest     2 24 30880
mounttest      2 25 35928
crashtest      2 26 25032
alloctest      2 27 26736
guest          2 28 41896
console        3 29 0
$ 
```

----------

- incremental progress fixing bugs as they arose
- guest kernel makes many assumptions about its environment
- first issue was privileged instructions (entry.S)

```
  # qemu -kernel starts at 0x1000. the instructions
        # there seem to be provided by qemu, as if it
        # were a ROM. the code at 0x1000 jumps to
        # 0x8000000, the _start function here,
        # in machine mode. each CPU starts here.
.section .data
.globl stack0
.section .text
.globl start
.section .text
.globl _entry
_entry:
  # set up a stack for C.
        # stack0 is declared in start.c,
        # with a 4096-byte stack per CPU.
        # sp = stack0 + (hartid * 4096)
        la sp, stack0
        li a0, 1024*4
  csrr a1, mhartid
        addi a1, a1, 1
        mul a0, a0, a1
        add sp, sp, a0
  # jump to start() in start.c
        call start
junk:
        j junk
```

- had to try to understand what level of emulation was necessary
- vs what approximations could be made -> hartid always zero
- to difficult to simulate full environment completely
- however, later on became difficult to tell which bugs were due to 
   faulty approximations

----------

- priviledged instructions

```
uint64*
getcsrptr(struct CSRegs *regs, uint16 code){
  switch(code){
    case 0xf14:
      return &regs->mhartid;
    case 0x300:
      return &regs->mstatus;
    case 0x341:
      return &regs->mepc;
    case 0x100:
      return &regs->sstatus;
    case 0x144:
      return &regs->sip;
  ...
```

----------

- hardware interaction

```
// qemu puts UART registers here in physical memory.
#define UART0 0x10000000L
#define UART0_IRQ 10

// virtio mmio interface
#define VIRTION(n) (0x10000000L + ((n+1) * 0x1000))
#define VIRTIO0_IRQ 1
#define VIRTIO1_IRQ 2

// local interrupt controller, which contains the timer.
#define CLINT 0x2000000L
#define CLINT_MTIMECMP(hartid) (CLINT + 0x4000 + 8*(hartid))
#define CLINT_MTIME (CLINT + 0xBFF8) // cycles since boot.

...
```

----------

- virtual memory

----------

- interrupts

```
if ((which_dev = devintr()) != 0) {

...
```

----------

- resources

- lots of time working with GDB
- incremental nature meant that we were never working with non-buggy code

- figuring out where / why guest kernel was crashing
- seeing how the normal xv6 initialization sequence proceeds
- GDB is wonderful, has hard time with jumps between guest and host

- RISC-V reader - good for understanding instruction encodings,
   priviledged ISA, register functions, etc
- only electronic copy online was in spanish

----------

