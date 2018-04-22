#### TimisoaraCTF 2018 - NG Child (250)  - Reverse Engineering

##### Challenge

Oh, you're here... Good, because I really need you at this moment.
So, you know I'm ambitious and trying to be accepted at one of the
best universities. Every year they are giving a challenge to students
that want to be accepted at their university. An accepted student
is called "Next Generation Child", you know all this Next-Gen hype...
I believe this challenge is not so hard and I want to prove that they
are Old-Gen. Ready?

NOTE: When you get something intelligible enclose only the last part in timctf{}

Author: 0xcpu 



#### Summary

The challenge is based in the following steps:

0. Patch the binary and remove the anti-debug techniques

1. Get 32 bytes from .data and perform a xor with the (n-odd character)
2. Perform a md5 to the result and check with the md5 hashes that they are in .rodata
  (You have the n-odd character)
3. If the md5 is correct, you have to dissasemble the 32 bytes generated with the xor operation.
4. The n-pair character is included in this assembly code.
5. In one function, perform a call to this assembly code, disassemble it and now you know the character that you need.
6. Perform it 12 times (because 12 hashes and 12 binary strings).
7. Get the flag



There we go!



#### Solution

Binary:

```
ng_child: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2d3481d0b7302267d6d01c8e4021ca735e5acf11, stripped
```



We patched the binary with radare2:

Before:

![](https://unam.re/static/files/ng_child1.png)

After:

![](https://unam.re/static/files/ng_child2.png)



Main code which perform the XOR, md5, and call <assembly code generated with the XOR>

![](https://unam.re/static/files/ng_child3.png)



So, disassemble first function and look that it is a simple xor between the first 32 byte got from .data and the first character.

![](https://unam.re/static/files/ng_child4.png)



We can know all odd characters now.

Getting the odd characters:

```Python
#!/usr/bin/bash

import string
import md5
import binascii

hashes = ["95a196021fa4e9574cd821c9d0ba041f",
        "5795b8d6e2435c5ecdac54375166b544",
        "5cc3e196973fbb79c9aa4e18027f866b",
        "fcc149646e5d3879134804646da90cea",
        "484ec01fb9e6449c0d80a716077702d1",
        "73c0dc9db84acd0c336522043b6fd4e3",
        "b466c3a7d2618bf6f61c6077e3bd6aa0",
        "e73273179f206a7db0d6960e96b84b82",
        "01a3e2b4e7523506929b4e3f3ad6dbbb",
        "bca5b1b2c5716cfd2c2e94cc07c26029",
        "7339e454bbe37d732026780d70d87c9a",
        "b5490761c3a6641e8f54de6a47a35eed"]


init = ["3c29373f97e120f8e829baef2000dc293429f8a8fc670f94abf89e492097e120", 
        "a1502936f1a140299ee12100d6213e3697e829a1f56ef1049ee629bae629a23e",
        "203187f7388ef7381ec031e0b0593de03db0e47f0088f031b9f738b32831a2f9",
        "23b941382186513800c229918738222b5138b0e47f158af0b68f38b32ab28e86",
        "3400c8382838b97080f938b95834abf03c2038b9ed76e90bb68631b5bae9b041",
        "20f839a8e120b89fa0972000d9f8a897e0a9fc67a9505cd89ca4abba492031a0",
        "2039313720ba68299fe12097e92400d7209ee829a1f56e15f115a79720a2f13f",
        "422ba3422b00d030f395422b9cea2b95f338a3f76c5298e33895422ba09cea2b",
        "00dbfb3f2aab6a23645b97eb2aafe32a2afbafff642aabffa9ff64ab6a23a837",
        "da283b3a28a958200792e928a9582100b9e1a95821abfd66b2e021aaf9322833",
        "26fe3faee726be99a6912600dffeae91e6affa61af5631de9aa2adbc4f2637a6",
        "2a00d6263626a76e9ee726a7462ab5ee223e26a7f368f73da8982faba4f7ae5f"]


index_init = 0
for h in hashes:
        for i in string.printable:
                m = md5.new()
                d = ord(i)
                out_x = ""
                index = 0
                while (index < len(init[index_init])):
                        f = init[index_init][index:index+2]
                        d_hex = int("0x"+f,16)^d
                        if f == "00":
                                out_x = out_x + "00"
                        elif len(hex(d_hex)) == 4:
                                out_x = out_x + hex(d_hex).replace("0x","")
                        elif len(hex(d_hex)) == 3:
                                out_x = out_x + hex(d_hex).replace("0x","0")
                        index = index + 2

                cadena = ""
                c1 = "".join(reversed([out_x[0:16][z:z+2] for z in range(0, 16, 2)])) #out_c[0:16]
                c2 = "".join(reversed([out_x[16:32][z:z+2] for z in range(0, 16, 2)]))#out_c[0:32]
                c3 = "".join(reversed([out_x[32:48][z:z+2] for z in range(0, 16, 2)]))#out_c[32:48]
                c4 = "".join(reversed([out_x[48:64][z:z+2] for z in range(0, 16, 2)]))#out_c[48:64]
                cadena = c1 + c2 + c3 + c4
                m.update(binascii.unhexlify(cadena))
                h_f = m.hexdigest()
                if h_f == h:
                        print i, m.hexdigest()
        index_init+=1

```



Result (Something is wrong with the script because "i" character doesn't appear -.-') 

```Bash
$ python hash.py 
h 95a196021fa4e9574cd821c9d0ba041f
a 5795b8d6e2435c5ecdac54375166b544
p 5cc3e196973fbb79c9aa4e18027f866b
p fcc149646e5d3879134804646da90cea
y 484ec01fb9e6449c0d80a716077702d1
h 73c0dc9db84acd0c336522043b6fd4e3
a b466c3a7d2618bf6f61c6077e3bd6aa0
c e73273179f206a7db0d6960e96b84b82
k 01a3e2b4e7523506929b4e3f3ad6dbbb
n 7339e454bbe37d732026780d70d87c9a
g b5490761c3a6641e8f54de6a47a35eed
```



Next important function includes the pair character in the 32 bytes generated with the xor.

![](https://unam.re/static/files/ng_child5.png)

![](https://unam.re/static/files/ng_child6.png)



![](https://unam.re/static/files/ng_child7.png)



How to solve it? Disassembly, and understand the code, it is easy (obviously, each 32 bytes generated will have different code..)

![](https://unam.re/static/files/ng_child8.png)



So, we modified our script to disassembly this code automatically.

```python
#!/usr/bin/bash

import string
import md5
import binascii
from pwn import *

hashes = ["95a196021fa4e9574cd821c9d0ba041f",
        "5795b8d6e2435c5ecdac54375166b544",
        "5cc3e196973fbb79c9aa4e18027f866b",
        "fcc149646e5d3879134804646da90cea",
        "484ec01fb9e6449c0d80a716077702d1",
        "73c0dc9db84acd0c336522043b6fd4e3",
        "b466c3a7d2618bf6f61c6077e3bd6aa0",
        "e73273179f206a7db0d6960e96b84b82",
        "01a3e2b4e7523506929b4e3f3ad6dbbb",
        "bca5b1b2c5716cfd2c2e94cc07c26029",
        "7339e454bbe37d732026780d70d87c9a",
        "b5490761c3a6641e8f54de6a47a35eed"]


init = ["3c29373f97e120f8e829baef2000dc293429f8a8fc670f94abf89e492097e120", 
        "a1502936f1a140299ee12100d6213e3697e829a1f56ef1049ee629bae629a23e",
        "203187f7388ef7381ec031e0b0593de03db0e47f0088f031b9f738b32831a2f9",
        "23b941382186513800c229918738222b5138b0e47f158af0b68f38b32ab28e86",
        "3400c8382838b97080f938b95834abf03c2038b9ed76e90bb68631b5bae9b041",
        "20f839a8e120b89fa0972000d9f8a897e0a9fc67a9505cd89ca4abba492031a0",
        "2039313720ba68299fe12097e92400d7209ee829a1f56e15f115a79720a2f13f",
        "422ba3422b00d030f395422b9cea2b95f338a3f76c5298e33895422ba09cea2b",
        "00dbfb3f2aab6a23645b97eb2aafe32a2afbafff642aabffa9ff64ab6a23a837",
        "da283b3a28a958200792e928a9582100b9e1a95821abfd66b2e021aaf9322833",
        "26fe3faee726be99a6912600dffeae91e6affa61af5631de9aa2adbc4f2637a6",
        "2a00d6263626a76e9ee726a7462ab5ee223e26a7f368f73da8982faba4f7ae5f"]


assembly = []

index_init = 0
for h in hashes:
        for i in string.printable:
                m = md5.new()
                d = ord(i)
                out_x = ""
                index = 0
                while (index < len(init[index_init])):
                        f = init[index_init][index:index+2]
                        d_hex = int("0x"+f,16)^d
                        if f == "00":
                                out_x = out_x + "00"
                        elif len(hex(d_hex)) == 4:
                                out_x = out_x + hex(d_hex).replace("0x","")
                        elif len(hex(d_hex)) == 3:
                                out_x = out_x + hex(d_hex).replace("0x","0")
                        index = index + 2

                # Divide en 4 partes e invierte
                cadena = ""
                c1 = "".join(reversed([out_x[0:16][z:z+2] for z in range(0, 16, 2)])) #out_c[0:16]
                c2 = "".join(reversed([out_x[16:32][z:z+2] for z in range(0, 16, 2)]))#out_c[0:32]
                c3 = "".join(reversed([out_x[32:48][z:z+2] for z in range(0, 16, 2)]))#out_c[32:48]
                c4 = "".join(reversed([out_x[48:64][z:z+2] for z in range(0, 16, 2)]))#out_c[48:64]
                cadena = c1 + c2 + c3 + c4
                m.update(binascii.unhexlify(cadena))
                h_f = m.hexdigest()
                if h_f == h:
                        assembly.append(binascii.unhexlify(cadena))
                        print i, m.hexdigest()
                #print out
        index_init+=1

context.arch = 'amd64'
for a in assembly:
        print "----------------------"
        print disasm(a)
```



Result:

```bash
h 95a196021fa4e9574cd821c9d0ba041f
a 5795b8d6e2435c5ecdac54375166b544
p 5cc3e196973fbb79c9aa4e18027f866b
p fcc149646e5d3879134804646da90cea
y 484ec01fb9e6449c0d80a716077702d1
h 73c0dc9db84acd0c336522043b6fd4e3
a b466c3a7d2618bf6f61c6077e3bd6aa0
c e73273179f206a7db0d6960e96b84b82
k 01a3e2b4e7523506929b4e3f3ad6dbbb
n 7339e454bbe37d732026780d70d87c9a
g b5490761c3a6641e8f54de6a47a35eed
----------------------
   0:   90                      nop
   1:   48 89 ff                mov    rdi,rdi
   4:   57                      push   rdi
   5:   5f                      pop    rdi
   6:   41 54                   push   r12
   8:   41 b4 00                mov    r12b,0x0
   b:   48 87 d2                xchg   rdx,rdx
   e:   41 80 fc 67             cmp    r12b,0x67
  12:   0f 94 c0                sete   al
  15:   90                      nop
  16:   41 5c                   pop    r12
  18:   48 89 ff                mov    rdi,rdi
  1b:   48 21 f6                and    rsi,rsi
  1e:   90                      nop
  1f:   c3                      ret
----------------------
   0:   48 21 c0                and    rax,rax
   3:   90                      nop
   4:   57                      push   rdi
   5:   48 31 c0                xor    rax,rax
   8:   57                      push   rdi
   9:   5f                      pop    rdi
   a:   40 b7 00                mov    dil,0x0
   d:   40 80 ff 65             cmp    dil,0x65
  11:   90                      nop
  12:   0f 94 c0                sete   al
  15:   48 89 f6                mov    rsi,rsi
  18:   5f                      pop    rdi
  19:   c3                      ret    
  1a:   48 87 db                xchg   rbx,rbx
  1d:   48 87 ff                xchg   rdi,rdi
----------------------
   0:   48 87 fe                xchg   rsi,rdi
   3:   48 87 f7                xchg   rdi,rsi
   6:   41 50                   push   r8
   8:   90                      nop
   9:   4d 29 c0                sub    r8,r8
   c:   90                      nop
   d:   41 b0 6e                mov    r8b,0x6e
  10:   41 80 f8 00             cmp    r8b,0x0
  14:   0f 94 c0                sete   al
  17:   4d 89 d2                mov    r10,r10
  1a:   41 58                   pop    r8
  1c:   c3                      ret    
  1d:   48 87 c9                xchg   rcx,rcx
----------------------
   0:   48 21 f6                and    rsi,rsi
   3:   51                      push   rcx
   4:   48 31 c9                xor    rcx,rcx
   7:   53                      push   rbx
   8:   5b                      pop    rbx
   9:   52                      push   rdx
   a:   48 f7 e1                mul    rcx
   d:   59                      pop    rcx
   e:   b2 00                   mov    dl,0x0
  10:   80 fa 65                cmp    dl,0x65
  13:   0f 94 c0                sete   al
  16:   48 21 f6                and    rsi,rsi
  19:   fe c2                   inc    dl
  1b:   5a                      pop    rdx
  1c:   c3                      ret    
  1d:   48 ff c6                inc    rsi
----------------------
   0:   09 c0                   or     eax,eax
   2:   41 51                   push   r9
   4:   41 b1 00                mov    r9b,0x0
   7:   4d 89 d2                mov    r10,r10
   a:   4d 21 c0                and    r8,r8
   d:   41 80 f9 72             cmp    r9b,0x72
  11:   90                      nop
  12:   0f 94 c0                sete   al
  15:   41 59                   pop    r9
  17:   45 38 c9                cmp    r9b,r9b
  1a:   90                      nop
  1b:   c3                      ret    
  1c:   cc                      int3   
  1d:   48 ff cf                dec    rdi
----------------------
   0:   f7 d0                   not    eax
   2:   48 89 c0                mov    rax,rax
   5:   51                      push   rcx
   6:   90                      nop
   7:   48 ff c0                inc    rax
   a:   90                      nop
   b:   b1 00                   mov    cl,0x0
   d:   48 ff c8                dec    rax
  10:   b0 34                   mov    al,0x34
  12:   38 c1                   cmp    cl,al
  14:   0f 94 c1                sete   cl
  17:   88 c8                   mov    al,cl
  19:   59                      pop    rcx
  1a:   48 21 d2                and    rdx,rdx
  1d:   c3                      ret    
  1e:   cc                      int3   
  1f:   f4                      hlt
----------------------
   0:   48 09 db                or     rbx,rbx
   3:   41 56                   push   r14
   5:   50                      push   rax
   6:   58                      pop    rax
   7:   41 b6 00                mov    r14b,0x0
   a:   45 88 f6                mov    r14b,r14b
   d:   41 80 fe 74             cmp    r14b,0x74
  11:   0f 94 c0                sete   al
  14:   48 89 ff                mov    rdi,rdi
  17:   41 5e                   pop    r14
  19:   90                      nop
  1a:   c3                      ret    
  1b:   41 f6 c6 74             test   r14b,0x74
  1f:   90                      nop
----------------------
   0:   53                      push   rbx
   1:   b3 00                   mov    bl,0x0
   3:   48 21 c0                and    rax,rax
   6:   48 21 f6                and    rsi,rsi
   9:   48 89 ff                mov    rdi,rdi
   c:   48 21 f6                and    rsi,rsi
   f:   90                      nop
  10:   80 fb 31                cmp    bl,0x31
  13:   0f 94 c0                sete   al
  16:   5b                      pop    rbx
  17:   90                      nop
  18:   48 89 ff                mov    rdi,rdi
  1b:   c3                      ret    
  1c:   48 21 f6                and    rsi,rsi
  1f:   5b                      pop    rbx
----------------------
   0:   48 01 c0                add    rax,rax
   3:   41 54                   push   r12
   5:   90                      nop
   6:   b0 00                   mov    al,0x0
   8:   41 88 c4                mov    r12b,al
   b:   41 80 fc 30             cmp    r12b,0x30
   f:   0f 94 c0                sete   al
  12:   41 0f 94 c4             sete   r12b
  16:   90                      nop
  17:   41 5c                   pop    r12
  19:   c3                      ret    
  1a:   48 01 c0                add    rax,rax
  1d:   0f 94 c2                sete   dl
----------------------
   0:   f7 d0                   not    eax
   2:   48 89 c0                mov    rax,rax
   5:   51                      push   rcx
   6:   90                      nop
   7:   48 ff c0                inc    rax
   a:   90                      nop
   b:   b1 00                   mov    cl,0x0
   d:   48 ff c8                dec    rax
  10:   b0 5f                   mov    al,0x5f
  12:   38 c1                   cmp    cl,al
  14:   0f 94 c1                sete   cl
  17:   88 c8                   mov    al,cl
  19:   59                      pop    rcx
  1a:   48 21 d2                and    rdx,rdx
  1d:   c3                      ret    
  1e:   cc                      int3   
  1f:   f4                      hlt
----------------------
   0:   09 c0                   or     eax,eax
   2:   41 51                   push   r9
   4:   41 b1 00                mov    r9b,0x0
   7:   4d 89 d2                mov    r10,r10
   a:   4d 21 c0                and    r8,r8
   d:   41 80 f9 5a             cmp    r9b,0x5a
  11:   90                      nop
  12:   0f 94 c0                sete   al
  15:   41 59                   pop    r9
  17:   45 38 c9                cmp    r9b,r9b
  1a:   90                      nop
  1b:   c3                      ret    
  1c:   cc                      int3   
  1d:   48 ff cf                dec    rdi
```



Result: 

```
# ./ng_child
New Generation Child Verifier
=============================
Are you a NG child or not!?
We are checking every child!
No one will pass by, no one!!!
(If you're not, come back next year ;-) )
hgaepnpeyrh4atc1k0inn_gZ
Got it!
Got it!
Got it!
Got it!
Got it!
Got it!
Got it!
Got it!
Got it!
Got it!
Got it!
Good!
```

```
happyhacking <- odds
gener4t10n_Z <- pairs
```



Reading the challenge, we know that the flag is:

```
timctf{gener4t10n_Z}
```



Happy Hacking!! 
