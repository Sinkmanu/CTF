#### 34C3 CTF 2017 - m0rph 49  - Reverse Engineering

##### Challenge

To get you started :)

files: Link

difficulty: easy

#### Summary

A stripped binary that compare character by character in a random order, also, the comparison is in an assembly code that it will change the comparison in each iteration in the loop.

#### Solution

Binary:

```
morph: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1c81eb4bc8b981ed39ef79801d6fef03d4d81056, stripped
```

The binary get one arguments, that it is the flag and first comparison is the length of the flag:

![](https://unam.re/static/files/m0rph_1.png)


After this, the binary have two call rax where execute assembly code that it is in the .rodata section, there we can see a character comparison. The character comparison is random, and in each execution will compare the characters in a different order.

![](https://unam.re/static/files/m0rph_2.png)

As the binary is PIE (Position Independent Executable), we can not know the address before the execution. A little trick is use the debugger to know the address that the debugger will use.

![](https://unam.re/static/files/m0rph_3.png)


![](https://unam.re/static/files/m0rph_4.png)

So, now we can to make and script to get all characters comparisons and generate the flag. I have used GDB for this purpose, the script will change the memory with the new characters until the flag is complete.

```
b *0x0000555555554b95
b *0x0000555555554bc6
set $pos = 0x0
run `python -c 'print "A"*23'`
set $flag = $rdi
while($pos<23)
step
step
step
x/2i $rip
set $var = $rip+0x3
set *(char *)$rdi=*(char *) $var 
print $rip
set $pos = $pos+0x1
printf "[+] Flag: %s\n",$flag
c
end
```

![](https://unam.re/static/files/m0rph.gif)
