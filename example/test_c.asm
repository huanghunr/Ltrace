rax      0x0000000000000038    rbx      0x0000000000000000    rcx      0x00007ffd31c4f598
rdx      0x0000769e3c32b380    rdi      0x0000769e3c35f2e0    rsi      0x0000769e3c35f8b8
r8       0x0000000000000000    r9       0x0000769e3c35c440    r10      0x00007ffd31c4f180
r11      0x0000000000000203    r12      0x0000619683a54180    r13      0x00007ffd31c4f580
r14      0x0000000000000000    r15      0x0000000000000000    rbp      0x0000000000000000
rsp      0x00007ffd31c4f580    rip      0x0000619683a54180    eflags   0x0000000000010206
cs       0x0000000000000033    ss       0x000000000000002b    ds       0x0000000000000000
es       0x0000000000000000    fs       0x0000000000000000    gs       0x0000000000000000
fs_base  0x0000769e3c316740    gs_base  0x0000000000000000
ZF=0x0 SF=0x0 CF=0x0 OF=0x0 PF=0x1 AF=0x0
mm0=0x0    st0=0.0    mm1=0x0    st1=0.0    mm2=0x0    st2=0.0    mm3=0x0    st3=0.0    mm4=0x0    st4=0.0    mm5=0x0    st5=0.0    mm6=0x0    st6=0.0    mm7=0x0    st7=0.0    xmm0=0x0    ymm0=0x0    xmm1=0xff00000000000000    ymm1=0xff00000000000000    xmm2=0x2c002b002a002a002a002a0000004554    ymm2=0x2c002b002a002a002a002a0000004554    xmm3=0x4554    ymm3=0x4554    xmm4=0x2a002c002b002a002a002a002a0000    ymm4=0x2a002c002b002a002a002a002a0000    xmm5=0x48    ymm5=0x48    xmm6=0xff0000000000000000000000000000    ymm6=0xff0000000000000000000000000000    xmm7=0x2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f    ymm7=0x2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f    xmm8=0x0    ymm8=0x0    xmm9=0x0    ymm9=0x0    xmm10=0x0    ymm10=0x0    xmm11=0x0    ymm11=0x0    xmm12=0x0    ymm12=0x0    xmm13=0x0    ymm13=0x0    xmm14=0x0    ymm14=0x0    xmm15=0x0    ymm15=0x0    
-----------
0x619683a54180	'test_c'!0x1180	endbr64	                              	
0x619683a54184	'test_c'!0x1184	xor   	ebp, ebp                      	ebp=0x0000000000000000 ZF=0x1
0x619683a54186	'test_c'!0x1186	mov   	r9, rdx                       	r9 =0x0000769e3c32b380
0x619683a54189	'test_c'!0x1189	pop   	rsi                           	rsi=0x0000000000000001
0x619683a5418a	'test_c'!0x118a	mov   	rdx, rsp                      	rdx=0x00007ffd31c4f588
0x619683a5418d	'test_c'!0x118d	and   	rsp, 0xfffffffffffffff0       	rsp=0x00007ffd31c4f580 ZF=0x0 PF=0x0
0x619683a54191	'test_c'!0x1191	push  	rax                           	rax=0x0000000000000038
0x619683a54192	'test_c'!0x1192	push  	rsp                           	rsp=0x00007ffd31c4f570
0x619683a54193	'test_c'!0x1193	xor   	r8d, r8d                      	r8d=0x0000000000000000 ZF=0x1 PF=0x1
0x619683a54196	'test_c'!0x1196	xor   	ecx, ecx                      	ecx=0x0000000000000000
0x619683a54198	'test_c'!0x1198	lea   	rdi, [rip + 0x1cd]            	rdi=0x0000619683a5436c
0x619683a5419f	'test_c'!0x119f	call  	qword ptr [rip + 0x2e33]      	rax=0x0000000000000038 rbx=0x0000000000000000 rcx=0x0000000000000000 rdx=0x00007ffd31c4f588 rsi=0x0000000000000001 rdi=0x0000619683a5436c rbp=0x0000000000000000 rsp=0x00007ffd31c4f568 r8 =0x0000000000000000 r9 =0x0000769e3c32b380 r10=0x00007ffd31c4f180 r11=0x0000000000000203 r12=0x0000619683a54180 r13=0x00007ffd31c4f580 r14=0x0000000000000000 r15=0x0000000000000000 rip=0x0000769e3c02a200
0x769e3c02a200	'libc.so.6'!0x2a200	__libc_start_main
0x619683a54000	'test_c'!0x1000	endbr64	                              	
0x619683a54004	'test_c'!0x1004	sub   	rsp, 8                        	rsp=0x00007ffd31c4f500
0x619683a54008	'test_c'!0x1008	mov   	rax, qword ptr [rip + 0x2fd9] 	rax=0x0000000000000000
0x619683a5400f	'test_c'!0x100f	test  	rax, rax                      	rax=0x0000000000000000 ZF=0x1
0x619683a54012	'test_c'!0x1012	je    	5                             	
0x619683a54016	'test_c'!0x1016	add   	rsp, 8                        	rsp=0x00007ffd31c4f508 ZF=0x0 PF=0x0
0x619683a5401a	'test_c'!0x101a	ret   	                              	
0x769e3c02a2b4	'libc.so.6'!0x2a2b4	unknown_lib_function(libc.so.6)
0x619683a54260	'test_c'!0x1260	endbr64	                              	
0x619683a54264	'test_c'!0x1264	jmp   	0xffffffffffffff7d            	
0x619683a541e0	'test_c'!0x11e0	lea   	rdi, [rip + 0x2e29]           	rdi=0x0000619683a57010
0x619683a541e7	'test_c'!0x11e7	lea   	rsi, [rip + 0x2e22]           	rsi=0x0000619683a57010
0x619683a541ee	'test_c'!0x11ee	sub   	rsi, rdi                      	rsi=0x0000000000000000
0x619683a541f1	'test_c'!0x11f1	mov   	rax, rsi                      	rax=0x0000000000000000
0x619683a541f4	'test_c'!0x11f4	shr   	rsi, 0x3f                     	rsi=0x0000000000000000
0x619683a541f8	'test_c'!0x11f8	sar   	rax, 3                        	rax=0x0000000000000000
0x619683a541fc	'test_c'!0x11fc	add   	rsi, rax                      	rsi=0x0000000000000000
0x619683a541ff	'test_c'!0x11ff	sar   	rsi, 1                        	rsi=0x0000000000000000
0x619683a54202	'test_c'!0x1202	je    	0x17                          	
0x619683a54218	'test_c'!0x1218	ret   	                              	
0x769e3c02a304	'libc.so.6'!0x2a304	unknown_lib_function(libc.so.6)
0x619683a5436c	'test_c'!0x136c	endbr64	                              	
0x619683a54370	'test_c'!0x1370	push  	rbp                           	rbp=0x00007ffd31c4f500
0x619683a54371	'test_c'!0x1371	mov   	rbp, rsp                      	rbp=0x00007ffd31c4f460
0x619683a54374	'test_c'!0x1374	sub   	rsp, 0x110                    	rsp=0x00007ffd31c4f350 ZF=0x0
0x619683a5437b	'test_c'!0x137b	mov   	rax, qword ptr fs:[0x28]      	rax=0x4f6cb11928c50100
0x619683a54384	'test_c'!0x1384	mov   	qword ptr [rbp - 8], rax      	mem=0x4f6cb11928c50100
0x619683a54388	'test_c'!0x1388	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1
0x619683a5438a	'test_c'!0x138a	lea   	rax, [rip + 0xcbf]            	rax=0x0000619683a55050
0x619683a54391	'test_c'!0x1391	mov   	rdi, rax                      	rdi=0x0000619683a55050
0x619683a54394	'test_c'!0x1394	call  	0xfffffffffffffd4d            	rax=0x0000619683a55050 rbx=0x00007ffd31c4f588 rcx=0x0000619683a56d78 rdx=0x00007ffd31c4f598 rsi=0x00007ffd31c4f588 rdi=0x0000619683a55050 rbp=0x00007ffd31c4f460 rsp=0x00007ffd31c4f348 r8 =0x0000000000000000 r9 =0x0000769e3c32b380 r10=0x00007ffd31c4f180 r11=0x0000000000000203 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a540e0
0x619683a540e0	'test_c'!0x10e0	endbr64	                              	
0x619683a540e4	'test_c'!0x10e4	jmp   	qword ptr [rip + 0x2e9e]      	mem=0x7be0000000000000
0x769e3c087be0	'libc.so.6'!0x87be0	_IO_puts
0x619683a54399	'test_c'!0x1399	lea   	rax, [rbp - 0x110]            	rax=0x00007ffd31c4f350
0x619683a543a0	'test_c'!0x13a0	mov   	rsi, rax                      	rsi=0x00007ffd31c4f350
0x619683a543a3	'test_c'!0x13a3	lea   	rax, [rip + 0xcc6]            	rax=0x0000619683a55070
0x619683a543aa	'test_c'!0x13aa	mov   	rdi, rax                      	rdi=0x0000619683a55070
0x619683a543ad	'test_c'!0x13ad	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a543b2	'test_c'!0x13b2	call  	0xfffffffffffffd9f            	rax=0x0000000000000000 rbx=0x00007ffd31c4f588 rcx=0x0000769e3c11c574 rdx=0x0000000000000000 rsi=0x00007ffd31c4f350 rdi=0x0000619683a55070 rbp=0x00007ffd31c4f460 rsp=0x00007ffd31c4f348 r8 =0x0000769e3c203b20 r9 =0x0000000000000410 r10=0x0000000000000001 r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a54150
0x619683a54150	'test_c'!0x1150	endbr64	                              	
0x619683a54154	'test_c'!0x1154	jmp   	qword ptr [rip + 0x2e66]      	mem=0xfe100000769e3c08
0x769e3c05fe10	'libc.so.6'!0x5fe10	__isoc99_scanf
0x619683a543b7	'test_c'!0x13b7	cmp   	eax, 1                        	eax=0x0000000000000001
0x619683a543ba	'test_c'!0x13ba	je    	0x2d                          	
0x619683a543e6	'test_c'!0x13e6	lea   	rax, [rbp - 0x110]            	rax=0x00007ffd31c4f350
0x619683a543ed	'test_c'!0x13ed	mov   	rsi, rax                      	rsi=0x00007ffd31c4f350
0x619683a543f0	'test_c'!0x13f0	lea   	rax, [rip + 0xc96]            	rax=0x0000619683a5508d
0x619683a543f7	'test_c'!0x13f7	mov   	rdi, rax                      	rdi=0x0000619683a5508d
0x619683a543fa	'test_c'!0x13fa	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a543ff	'test_c'!0x13ff	call  	0xfffffffffffffd12            	rax=0x0000000000000000 rbx=0x00007ffd31c4f588 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x00007ffd31c4f350 rdi=0x0000619683a5508d rbp=0x00007ffd31c4f460 rsp=0x00007ffd31c4f348 r8 =0x000000000000000a r9 =0x00000000000000ff r10=0xffffffffffffff88 r11=0x0000769e3c2038e0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a54110
0x619683a54110	'test_c'!0x1110	endbr64	                              	
0x619683a54114	'test_c'!0x1114	jmp   	qword ptr [rip + 0x2e86]      	mem=0x01000000769e3c13
0x769e3c060100	'libc.so.6'!0x60100	printf
0x619683a54404	'test_c'!0x1404	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a54409	'test_c'!0x1409	call  	0xfffffffffffffead            	rax=0x0000000000000000 rbx=0x00007ffd31c4f588 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x00006196a2e882a0 rdi=0x00007ffd31c4f170 rbp=0x00007ffd31c4f460 rsp=0x00007ffd31c4f348 r8 =0x0000000000000073 r9 =0x0000000000000000 r10=0x00000000ffffffff r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a542b5
0x619683a542b5	'test_c'!0x12b5	endbr64	                              	
0x619683a542b9	'test_c'!0x12b9	push  	rbp                           	rbp=0x00007ffd31c4f460
0x619683a542ba	'test_c'!0x12ba	mov   	rbp, rsp                      	rbp=0x00007ffd31c4f340
0x619683a542bd	'test_c'!0x12bd	sub   	rsp, 0x420                    	rsp=0x00007ffd31c4ef20 ZF=0x0 PF=0x0
0x619683a542c4	'test_c'!0x12c4	mov   	rax, qword ptr fs:[0x28]      	rax=0x4f6cb11928c50100
0x619683a542cd	'test_c'!0x12cd	mov   	qword ptr [rbp - 8], rax      	mem=0x4f6cb11928c50100
0x619683a542d1	'test_c'!0x12d1	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1 PF=0x1
0x619683a542d3	'test_c'!0x12d3	lea   	rax, [rip + 0xd41]            	rax=0x0000619683a5501b
0x619683a542da	'test_c'!0x12da	mov   	rsi, rax                      	rsi=0x0000619683a5501b
0x619683a542dd	'test_c'!0x12dd	lea   	rax, [rip + 0xd39]            	rax=0x0000619683a5501d
0x619683a542e4	'test_c'!0x12e4	mov   	rdi, rax                      	rdi=0x0000619683a5501d
0x619683a542e7	'test_c'!0x12e7	call  	0xfffffffffffffe5a            	rax=0x0000619683a5501d rbx=0x00007ffd31c4f588 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x0000619683a5501b rdi=0x0000619683a5501d rbp=0x00007ffd31c4f340 rsp=0x00007ffd31c4ef18 r8 =0x0000000000000073 r9 =0x0000000000000000 r10=0x00000000ffffffff r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a54140
0x619683a54140	'test_c'!0x1140	endbr64	                              	
0x619683a54144	'test_c'!0x1144	jmp   	qword ptr [rip + 0x2e6e]      	mem=0x5e600000769e3c12
0x769e3c085e60	'libc.so.6'!0x85e60	_IO_fopen
0x619683a542ec	'test_c'!0x12ec	mov   	qword ptr [rbp - 0x418], rax  	mem=0x00006196a2e896c0
0x619683a542f3	'test_c'!0x12f3	cmp   	qword ptr [rbp - 0x418], 0    	mem=0x00006196a2e896c0 ZF=0x0
0x619683a542fb	'test_c'!0x12fb	jne   	0x2d                          	
0x619683a54327	'test_c'!0x1327	mov   	rdx, qword ptr [rbp - 0x418]  	rdx=0x00006196a2e896c0
0x619683a5432e	'test_c'!0x132e	lea   	rax, [rbp - 0x410]            	rax=0x00007ffd31c4ef30
0x619683a54335	'test_c'!0x1335	mov   	esi, 0x400                    	esi=0x0000000000000400
0x619683a5433a	'test_c'!0x133a	mov   	rdi, rax                      	rdi=0x00007ffd31c4ef30
0x619683a5433d	'test_c'!0x133d	call  	0xfffffffffffffde4            	rax=0x00007ffd31c4ef30 rbx=0x00007ffd31c4f588 rcx=0x0000769e3c11b175 rdx=0x00006196a2e896c0 rsi=0x0000000000000400 rdi=0x00007ffd31c4ef30 rbp=0x00007ffd31c4f340 rsp=0x00007ffd31c4ef18 r8 =0x0000000000000008 r9 =0x0000000000000001 r10=0x0000000000000000 r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a54120
0x619683a54120	'test_c'!0x1120	endbr64	                              	
0x619683a54124	'test_c'!0x1124	jmp   	qword ptr [rip + 0x2e7e]      	mem=0x5b300000769e3c06
0x769e3c085b30	'libc.so.6'!0x85b30	_IO_fgets
0x619683a54342	'test_c'!0x1342	mov   	rax, qword ptr [rbp - 0x418]  	rax=0x00006196a2e896c0
0x619683a54349	'test_c'!0x1349	mov   	rdi, rax                      	rdi=0x00006196a2e896c0
0x619683a5434c	'test_c'!0x134c	call  	0xfffffffffffffda5            	rax=0x00006196a2e896c0 rbx=0x00007ffd31c4f588 rcx=0x000000005d17675f rdx=0x00000000fbad2488 rsi=0x00006196a2e898a1 rdi=0x00006196a2e896c0 rbp=0x00007ffd31c4f340 rsp=0x00007ffd31c4ef18 r8 =0x00006196a2e8990d r9 =0x0000000000000410 r10=0x0000000000000001 r11=0x0000000000000346 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a540f0
0x619683a540f0	'test_c'!0x10f0	endbr64	                              	
0x619683a540f4	'test_c'!0x10f4	jmp   	qword ptr [rip + 0x2e96]      	mem=0x52900000769e3c08
0x769e3c085290	'libc.so.6'!0x85290	fclose
0x619683a54351	'test_c'!0x1351	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a54356	'test_c'!0x1356	mov   	rdx, qword ptr [rbp - 8]      	rdx=0x4f6cb11928c50100
0x619683a5435a	'test_c'!0x135a	sub   	rdx, qword ptr fs:[0x28]      	rdx=0x0000000000000000 ZF=0x1 PF=0x1
0x619683a54363	'test_c'!0x1363	je    	8                             	
0x619683a5436a	'test_c'!0x136a	leave 	                              	
0x619683a5436b	'test_c'!0x136b	ret   	                              	
0x619683a5440e	'test_c'!0x140e	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a54413	'test_c'!0x1413	call  	0xfffffffffffffe57            	rax=0x0000000000000000 rbx=0x00007ffd31c4f588 rcx=0x0000000000000001 rdx=0x0000000000000000 rsi=0x00006196a2e896b0 rdi=0x0000000000000000 rbp=0x00007ffd31c4f460 rsp=0x00007ffd31c4f348 r8 =0x00006196a2e88010 r9 =0x0000000000000007 r10=0x00006196a2e896c0 r11=0x9d59190170b8fc7e r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a54269
0x619683a54269	'test_c'!0x1269	endbr64	                              	
0x619683a5426d	'test_c'!0x126d	push  	rbp                           	rbp=0x00007ffd31c4f460
0x619683a5426e	'test_c'!0x126e	mov   	rbp, rsp                      	rbp=0x00007ffd31c4f340
0x619683a54271	'test_c'!0x1271	mov   	ecx, 0                        	ecx=0x0000000000000000
0x619683a54276	'test_c'!0x1276	mov   	edx, 0                        	edx=0x0000000000000000
0x619683a5427b	'test_c'!0x127b	mov   	esi, 0                        	esi=0x0000000000000000
0x619683a54280	'test_c'!0x1280	mov   	edi, 0                        	edi=0x0000000000000000
0x619683a54285	'test_c'!0x1285	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a5428a	'test_c'!0x128a	call  	0xfffffffffffffea7            	rax=0x0000000000000000 rbx=0x00007ffd31c4f588 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x0000000000000000 rdi=0x0000000000000000 rbp=0x00007ffd31c4f340 rsp=0x00007ffd31c4f338 r8 =0x00006196a2e88010 r9 =0x0000000000000007 r10=0x00006196a2e896c0 r11=0x9d59190170b8fc7e r12=0x0000000000000001 r13=0x0000000000000000 r14=0x0000619683a56d78 r15=0x0000769e3c35e000 rip=0x0000619683a54130
0x619683a54130	'test_c'!0x1130	endbr64	                              	
0x619683a54134	'test_c'!0x1134	jmp   	qword ptr [rip + 0x2e76]      	mem=0x60a00000769e3c08
0x769e3c1260a0	'libc.so.6'!0x1260a0	ptrace
0x619683a5428f	'test_c'!0x128f	cmp   	rax, -1                       	rax=0x0000000000000000 ZF=0x0 CF=0x1 PF=0x0 AF=0x1
0x619683a54293	'test_c'!0x1293	jne   	0x1c                          	
0x619683a542ae	'test_c'!0x12ae	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a542b3	'test_c'!0x12b3	pop   	rbp                           	rbp=0x00007ffd31c4f460
0x619683a542b4	'test_c'!0x12b4	ret   	                              	
0x619683a54418	'test_c'!0x1418	mov   	eax, 0                        	eax=0x0000000000000000
0x619683a5441d	'test_c'!0x141d	mov   	rdx, qword ptr [rbp - 8]      	rdx=0x4f6cb11928c50100
0x619683a54421	'test_c'!0x1421	sub   	rdx, qword ptr fs:[0x28]      	rdx=0x0000000000000000 ZF=0x1 CF=0x0 PF=0x1 AF=0x0
0x619683a5442a	'test_c'!0x142a	je    	8                             	
0x619683a54431	'test_c'!0x1431	leave 	                              	
0x619683a54432	'test_c'!0x1432	ret   	                              	
0x769e3c02a1ca	'libc.so.6'!0x2a1ca	unknown_lib_function(libc.so.6)
0x619683a54220	'test_c'!0x1220	endbr64	                              	
0x619683a54224	'test_c'!0x1224	cmp   	byte ptr [rip + 0x2dfd], 0    	mem=0x000000769e3c2044 ZF=0x1 PF=0x1
0x619683a5422b	'test_c'!0x122b	jne   	0x2e                          	
0x619683a5422d	'test_c'!0x122d	push  	rbp                           	rbp=0x00007ffd31c4f370
0x619683a5422e	'test_c'!0x122e	cmp   	qword ptr [rip + 0x2dc2], 0   	mem=0x0000000000000000 ZF=0x0
0x619683a54236	'test_c'!0x1236	mov   	rbp, rsp                      	rbp=0x00007ffd31c4f340
0x619683a54239	'test_c'!0x1239	je    	0xf                           	
0x619683a5423b	'test_c'!0x123b	mov   	rdi, qword ptr [rip + 0x2dc6] 	rdi=0x0000619683a57008
0x619683a54242	'test_c'!0x1242	call  	0xfffffffffffffe8f            	rax=0x0000000000000001 rbx=0x0000619683a56d78 rcx=0x00007ffd31c4f2b0 rdx=0x0000000000000000 rsi=0x0000000000000004 rdi=0x0000619683a57008 rbp=0x00007ffd31c4f340 rsp=0x00007ffd31c4f338 r8 =0x00007ffd31c4f380 r9 =0x0000000000000000 r10=0x00007ffd31c4f32f r11=0x00007ffd31c4f330 r12=0x0000769e3c35f2e0 r13=0x0000619683a56d78 r14=0x0000000000000000 r15=0x0000769e3c35f2e0 rip=0x0000619683a540d0
0x619683a540d0	'test_c'!0x10d0	endbr64	                              	
0x619683a540d4	'test_c'!0x10d4	jmp   	qword ptr [rip + 0x2f1e]      	mem=0x72c0000000000000
0x769e3c0472c0	'libc.so.6'!0x472c0	__cxa_finalize
0x619683a54247	'test_c'!0x1247	call  	0xffffffffffffff6a            	rax=0x0000000000000001 rbx=0x0000619683a56d78 rcx=0x0000000000000000 rdx=0x0000000000000001 rsi=0x0000000000000000 rdi=0x0000619683a57008 rbp=0x00007ffd31c4f340 rsp=0x00007ffd31c4f338 r8 =0x00007ffd31c4f380 r9 =0x0000000000000000 r10=0x00007ffd31c4f32f r11=0x00007ffd31c4f330 r12=0x0000769e3c35f2e0 r13=0x0000619683a56d78 r14=0x0000000000000000 r15=0x0000769e3c35f2e0 rip=0x0000619683a541b0
0x619683a541b0	'test_c'!0x11b0	lea   	rdi, [rip + 0x2e59]           	rdi=0x0000619683a57010
0x619683a541b7	'test_c'!0x11b7	lea   	rax, [rip + 0x2e52]           	rax=0x0000619683a57010
0x619683a541be	'test_c'!0x11be	cmp   	rax, rdi                      	rax=0x0000619683a57010 ZF=0x1 PF=0x1
0x619683a541c1	'test_c'!0x11c1	je    	0x18                          	
0x619683a541d8	'test_c'!0x11d8	ret   	                              	
0x619683a5424c	'test_c'!0x124c	mov   	byte ptr [rip + 0x2dd5], 1    	mem=0x010000769e3c2044
0x619683a54253	'test_c'!0x1253	pop   	rbp                           	rbp=0x00007ffd31c4f370
0x619683a54254	'test_c'!0x1254	ret   	                              	
0x769e3c3270f2	'ld-linux-x86-64.so.2'!0x10f2	unknown_lib_function(ld-linux-x86-64.so.2)
0x619683a54434	'test_c'!0x1434	endbr64	                              	
0x619683a54438	'test_c'!0x1438	sub   	rsp, 8                        	rsp=0x00007ffd31c4f370
0x619683a5443c	'test_c'!0x143c	add   	rsp, 8                        	rsp=0x00007ffd31c4f378 PF=0x1
0x619683a54440	'test_c'!0x1440	ret   	                              	
0x769e3c32b578	'ld-linux-x86-64.so.2'!0x5578	unknown_lib_function(ld-linux-x86-64.so.2)
0x769e3c047a76	'libc.so.6'!0x47a76	unknown_lib_function(libc.so.6)
