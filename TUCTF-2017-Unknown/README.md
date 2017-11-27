TUCTF CTF 2017 - Unknown 200 - Reversing Engineering 

##### Challenge

Diggin through some old files we discovered this binary. Although despite our inspection we can't figure out what it does. Or what it wants...

unknown - md5: 9f08f6e8240d4a0e098c4065c5737ca6


#### Summary

It is a typical reverse engineering task where we have to get the password (that in this case is the flag). For this purpose I have used the tools, objdump and radare2, and Python to develop the solution.

#### Solution

```bash
$ file unknown
unknown: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=53ec94bd1406ec6b9a28f5308a92e4d906444edb, stripped
```

Looking strings to find where the flag is printed and reverse it.

```bash
[0x00401d68]> iz
vaddr=0x00401d64 paddr=0x00001d64 ordinal=000 sz=18 len=17 section=.rodata type=ascii string=0123456789abcdef=
vaddr=0x00401d76 paddr=0x00001d76 ordinal=001 sz=11 len=10 section=.rodata type=ascii string=Try again.
vaddr=0x00401d81 paddr=0x00001d81 ordinal=002 sz=12 len=11 section=.rodata type=ascii string=Still nope.
vaddr=0x00401d8d paddr=0x00001d8d ordinal=003 sz=6 len=5 section=.rodata type=ascii string=Nope.
vaddr=0x00401d93 paddr=0x00001d93 ordinal=004 sz=25 len=24 section=.rodata type=ascii string=Congraz the flag is: %s\n

[0x00401d68]> axt @ 0x00401d93
data 0x401cbe mov edi, str.Congraz_the_flag_is:__s_n in main
```

![](https://unam.re/static/files/function1.png)

We found the function that executes the encoding and compare with the encoded password (flag). In order to resolve the challenge, we have to reverse this function:


![](https://unam.re/static/files/reverse1.png)


I debugged a bit the first function with GDB and I saw fastly that it returned a md4sum. So, this function will get the md4 hash the n-character of the string and split this string to use just the last 8 characters. After, it converts these characters to numbers and does the following operations:

```asm
0x00401f09	mul rbx                                                                                                                                                                 
0x00401f0c	and eax, 0xffffffff                                                                                                                                                     
0x00401f0f	rol eax, 0x15     
```


The result will be compared with the encoded flag:

```
0x00401f12	movabs rcx, 0x401dac        
0x00401f1	mov rcx, qword [rcx + rsi*4]                                                                                                                                            
0x00401f20	cmp eax, ecx                                                                                                                                                            
0x00401f22	je 0x401f2e     
```

So, to generate our script, we just need the encoded flag and it can be found in the address *0x401dac*

```bash
$ objdump -j .DATA -s unknown

unknown:     formato del fichero elf64-x86-64

Contenido de la sección .DATA:
 401dac 7ab5fafd a7492403 2138385f 7ab5fafd  z....I$.!88_z...
 401dbc 025e4325 0debe259 d756d75e 23f0ff5c  .^C%...Y.V.^#..\
 401dcc f3bd3992 9b7f2cf6 5f3fe163 848e33d6  ..9...,._?.c..3.
 401ddc 23f0ff5c efbd20ff 8e921fc5 5f3fe163  #..\.. ....._?.c
 401dec efbd20ff 8e921fc5 71109db5 9b7f2cf6  .. .....q.....,.
 401dfc 8e921fc5 70988d38 efbd20ff bac5ecce  ....p..8.. .....
 401e0c 6b1352a9 41087196 efbd20ff 8e921fc5  k.R.A.q... .....
 401e1c fddf36f5 bac5ecce 6b1352a9 c4dad7c5  ..6.....k.R.....
 401e2c efbd20ff 612aa912 5f3fe163 71109db5  .. .a*.._?.cq...
 401e3c efbd20ff 70988d38 5f3fe163 4e3578cd  .. .p..8_?.cN5x.
 401e4c efbd20ff 194418f2 bac5ecce 4e3578cd  .. ..D......N5x.
 401e5c 8e921fc5 dcbfa83c 9b7f2cf6 dcbfa83c  .......<..,....<
 401e6c 194418f2 bac5ecce 8e921fc5 dcbfa83c  .D.............<
 401e7c 6b1352a9 4451f32f a75e16ba cd841bef  k.R.DQ./.^......
 401e8c 38000000                             8...
```

As Intel x86-64 is little endian, in our script we have to write the bytes in reverse.



Here's the python script that get the flag. 


```python
#!/usr/bin/env python

from Crypto.Hash import MD4
import string

rol = lambda val, r_bits, max_bits=32: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

table = ['fdfab57a','32449a7'
,'5f383821', 'fdfab57a'
,'25435e02','59e2eb0d'
,'5ed756d7','5cfff023'
,'9239bdf3','f62c7f9b'
,'63e13f5f','d6338e84'
,'5cfff023','ff20bdef'
,'c51f928e','63e13f5f'
,'ff20bdef','c51f928e'
,'b59d1071','f62c7f9b'
,'c51f928e','388d9870'
,'ff20bdef','ceecc5ba'
,'a952136b','96710841'
,'ff20bdef','c51f928e'
,'f536dffd','ceecc5ba'
,'a952136b','c5d7dac4'
,'ff20bdef','12a92a61'
,'63e13f5f','b59d1071'
,'ff20bdef','388d9870'
,'63e13f5f','cd78354e'
,'ff20bdef','f2184419'
,'ceecc5ba','cd78354e'
,'c51f928e','3ca8bfdc'
,'f62c7f9b','3ca8bfdc'
,'f2184419','ceecc5ba'
,'c51f928e','3ca8bfdc'
,'a952136b','2ff35144'
,'ba165ea7','ef1b84cd'
,'e6894955']

flag = []                                                                                                                                                                                                          
                                                                                                                                                                                                                   
for z in table:                                                                                                                                                                                                    
        for i in string.printable:                                                                                                                                                                                 
                h = MD4.new()                                                                                                                                                                                      
                h.update(i)                                                                                                                                                                                        
                cad = h.hexdigest()[24:]                                                                                                                                                                           
                number = int(cad, 16)                                                                                                                                                                              
                cal = (number * 0x7a69) & 0xffffffff                                                                                                                                                               
                n = hex(rol(cal,0x15))[2:]                                                                                                                                                                         
                if (z == n):                                                                                                                                                                                       
                        flag.append(i)                                                                                                                                                                             

print "".join(flag)
```

and the result:

```bash
$ python unknown.py 
TUCTF{w3lc0m3_70_7uc7f_4nd_7h4nk_y0u_f0r_p4r71c1p471n6!}
```














