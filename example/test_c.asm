rax      0x0000000000000038    rbx      0x0000000000000000    rcx      0x00007ffdee3d66a8
rdx      0x00007a3385ace380    rdi      0x00007a3385b022e0    rsi      0x00007a3385b028b8
r8       0x0000000000000000    r9       0x00007a3385aff440    r10      0x00007ffdee3d6290
r11      0x0000000000000203    r12      0x000057d02f549180    r13      0x00007ffdee3d6690
r14      0x0000000000000000    r15      0x0000000000000000    rbp      0x0000000000000000
rsp      0x00007ffdee3d6690    rip      0x000057d02f549180    eflags   0x0000000000010202
cs       0x0000000000000033    ss       0x000000000000002b    ds       0x0000000000000000
es       0x0000000000000000    fs       0x0000000000000000    gs       0x0000000000000000
fs_base  0x00007a3385ab8740    gs_base  0x0000000000000000
ZF=0x0 SF=0x0 CF=0x0 OF=0x0 PF=0x0 AF=0x0
mm0=0x0    st0=0.0    mm1=0x0    st1=0.0    mm2=0x0    st2=0.0    mm3=0x0    st3=0.0    mm4=0x0    st4=0.0    mm5=0x0    st5=0.0    mm6=0x0    st6=0.0    mm7=0x0    st7=0.0    xmm0=0x0    ymm0=0x0    xmm1=0xff00000000000000    ymm1=0xff00000000000000    xmm2=0x2c002b002a002a002a002a0000004554    ymm2=0x2c002b002a002a002a002a0000004554    xmm3=0x4554    ymm3=0x4554    xmm4=0x2a002c002b002a002a002a002a0000    ymm4=0x2a002c002b002a002a002a002a0000    xmm5=0x48    ymm5=0x48    xmm6=0xff0000000000000000000000000000    ymm6=0xff0000000000000000000000000000    xmm7=0x2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f    ymm7=0x2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f    xmm8=0x0    ymm8=0x0    xmm9=0x0    ymm9=0x0    xmm10=0x0    ymm10=0x0    xmm11=0x0    ymm11=0x0    xmm12=0x0    ymm12=0x0    xmm13=0x0    ymm13=0x0    xmm14=0x0    ymm14=0x0    xmm15=0x0    ymm15=0x0    
-----------
0x57d02f549180	'test_c'!0x1180	endbr64	                              	
0x57d02f549184	'test_c'!0x1184	xor   	ebp, ebp                      	ebp=0x0000000000000000 ZF=0x1 PF=0x1
0x57d02f549186	'test_c'!0x1186	mov   	r9, rdx                       	r9 =0x00007a3385ace380
0x57d02f549189	'test_c'!0x1189	pop   	rsi                           	rsi=0x0000000000000001
0x57d02f54918a	'test_c'!0x118a	mov   	rdx, rsp                      	rdx=0x00007ffdee3d6698
0x57d02f54918d	'test_c'!0x118d	and   	rsp, 0xfffffffffffffff0       	rsp=0x00007ffdee3d6690 ZF=0x0
0x57d02f549191	'test_c'!0x1191	push  	rax                           	rax=0x0000000000000038
0x57d02f549192	'test_c'!0x1192	push  	rsp                           	rsp=0x00007ffdee3d6680
0x57d02f549193	'test_c'!0x1193	xor   	r8d, r8d                      	r8d=0x0000000000000000 ZF=0x1
0x57d02f549196	'test_c'!0x1196	xor   	ecx, ecx                      	ecx=0x0000000000000000
0x57d02f549198	'test_c'!0x1198	lea   	rdi, [rip + 0x1cd]            	rdi=0x000057d02f54936c
0x57d02f54919f	'test_c'!0x119f	call  	qword ptr [rip + 0x2e33]      	rax=0x0000000000000038 rbx=0x0000000000000000 rcx=0x0000000000000000 rdx=0x00007ffdee3d6698 rsi=0x0000000000000001 rdi=0x000057d02f54936c rbp=0x0000000000000000 rsp=0x00007ffdee3d6678 r8 =0x0000000000000000 r9 =0x00007a3385ace380 r10=0x00007ffdee3d6290 r11=0x0000000000000203 r12=0x000057d02f549180 r13=0x00007ffdee3d6690 r14=0x0000000000000000 r15=0x0000000000000000 rip=0x00007a338582a200
0x7a338582a200	'libc.so.6'!0x2a200	__libc_start_main
0x57d02f549000	'test_c'!0x1000	endbr64	                              	
0x57d02f549004	'test_c'!0x1004	sub   	rsp, 8                        	rsp=0x00007ffdee3d6610 PF=0x0
0x57d02f549008	'test_c'!0x1008	mov   	rax, qword ptr [rip + 0x2fd9] 	rax=0x0000000000000000
0x57d02f54900f	'test_c'!0x100f	test  	rax, rax                      	rax=0x0000000000000000 ZF=0x1 PF=0x1
0x57d02f549012	'test_c'!0x1012	je    	5                             	
0x57d02f549016	'test_c'!0x1016	add   	rsp, 8                        	rsp=0x00007ffdee3d6618 ZF=0x0
0x57d02f54901a	'test_c'!0x101a	ret   	                              	
0x7a338582a2b4	'libc.so.6'!0x2a2b4	unknown_lib_function(libc.so.6)
0x57d02f549260	'test_c'!0x1260	endbr64	                              	
0x57d02f549264	'test_c'!0x1264	jmp   	0xffffffffffffff7d            	
0x57d02f5491e0	'test_c'!0x11e0	lea   	rdi, [rip + 0x2e29]           	rdi=0x000057d02f54c010
0x57d02f5491e7	'test_c'!0x11e7	lea   	rsi, [rip + 0x2e22]           	rsi=0x000057d02f54c010
0x57d02f5491ee	'test_c'!0x11ee	sub   	rsi, rdi                      	rsi=0x0000000000000000
0x57d02f5491f1	'test_c'!0x11f1	mov   	rax, rsi                      	rax=0x0000000000000000
0x57d02f5491f4	'test_c'!0x11f4	shr   	rsi, 0x3f                     	rsi=0x0000000000000000
0x57d02f5491f8	'test_c'!0x11f8	sar   	rax, 3                        	rax=0x0000000000000000
0x57d02f5491fc	'test_c'!0x11fc	add   	rsi, rax                      	rsi=0x0000000000000000
0x57d02f5491ff	'test_c'!0x11ff	sar   	rsi, 1                        	rsi=0x0000000000000000
0x57d02f549202	'test_c'!0x1202	je    	0x17                          	
0x57d02f549218	'test_c'!0x1218	ret   	                              	
0x7a338582a304	'libc.so.6'!0x2a304	unknown_lib_function(libc.so.6)
0x57d02f54936c	'test_c'!0x136c	endbr64	                              	
0x57d02f549370	'test_c'!0x1370	push  	rbp                           	rbp=0x00007ffdee3d6610
0x57d02f549371	'test_c'!0x1371	mov   	rbp, rsp                      	rbp=0x00007ffdee3d6570
0x57d02f549374	'test_c'!0x1374	sub   	rsp, 0x110                    	rsp=0x00007ffdee3d6460 ZF=0x0
0x57d02f54937b	'test_c'!0x137b	mov   	rax, qword ptr fs:[0x28]      	rax=0x6c4e721c27e83400
0x57d02f549384	'test_c'!0x1384	mov   	qword ptr [rbp - 8], rax      	mem=0x6c4e721c27e83400
0x57d02f549388	'test_c'!0x1388	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1
0x57d02f54938a	'test_c'!0x138a	lea   	rax, [rip + 0xcbf]            	rax=0x000057d02f54a050
0x57d02f549391	'test_c'!0x1391	mov   	rdi, rax                      	rdi=0x000057d02f54a050
0x57d02f549394	'test_c'!0x1394	call  	0xfffffffffffffd4d            	rax=0x000057d02f54a050 rbx=0x00007ffdee3d6698 rcx=0x000057d02f54bd78 rdx=0x00007ffdee3d66a8 rsi=0x00007ffdee3d6698 rdi=0x000057d02f54a050 rbp=0x00007ffdee3d6570 rsp=0x00007ffdee3d6458 r8 =0x0000000000000000 r9 =0x00007a3385ace380 r10=0x00007ffdee3d6290 r11=0x0000000000000203 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f5490e0
0x57d02f5490e0	'test_c'!0x10e0	endbr64	                              	
0x57d02f5490e4	'test_c'!0x10e4	jmp   	qword ptr [rip + 0x2e9e]      	mem=0x7be0000000000000
0x7a3385887be0	'libc.so.6'!0x87be0	_IO_puts
0x57d02f549399	'test_c'!0x1399	lea   	rax, [rbp - 0x110]            	rax=0x00007ffdee3d6460
0x57d02f5493a0	'test_c'!0x13a0	mov   	rsi, rax                      	rsi=0x00007ffdee3d6460
0x57d02f5493a3	'test_c'!0x13a3	lea   	rax, [rip + 0xcc6]            	rax=0x000057d02f54a070
0x57d02f5493aa	'test_c'!0x13aa	mov   	rdi, rax                      	rdi=0x000057d02f54a070
0x57d02f5493ad	'test_c'!0x13ad	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f5493b2	'test_c'!0x13b2	call  	0xfffffffffffffd9f            	rax=0x0000000000000000 rbx=0x00007ffdee3d6698 rcx=0x00007a338591c574 rdx=0x0000000000000000 rsi=0x00007ffdee3d6460 rdi=0x000057d02f54a070 rbp=0x00007ffdee3d6570 rsp=0x00007ffdee3d6458 r8 =0x00007a3385a03b20 r9 =0x0000000000000410 r10=0x0000000000000001 r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f549150
0x57d02f549150	'test_c'!0x1150	endbr64	                              	
0x57d02f549154	'test_c'!0x1154	jmp   	qword ptr [rip + 0x2e66]      	mem=0xfe1000007a338588
0x7a338585fe10	'libc.so.6'!0x5fe10	__isoc99_scanf
0x57d02f5493b7	'test_c'!0x13b7	cmp   	eax, 1                        	eax=0x0000000000000001
0x57d02f5493ba	'test_c'!0x13ba	je    	0x2d                          	
0x57d02f5493e6	'test_c'!0x13e6	lea   	rax, [rbp - 0x110]            	rax=0x00007ffdee3d6460
0x57d02f5493ed	'test_c'!0x13ed	mov   	rsi, rax                      	rsi=0x00007ffdee3d6460
0x57d02f5493f0	'test_c'!0x13f0	lea   	rax, [rip + 0xc96]            	rax=0x000057d02f54a08d
0x57d02f5493f7	'test_c'!0x13f7	mov   	rdi, rax                      	rdi=0x000057d02f54a08d
0x57d02f5493fa	'test_c'!0x13fa	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f5493ff	'test_c'!0x13ff	call  	0xfffffffffffffd12            	rax=0x0000000000000000 rbx=0x00007ffdee3d6698 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x00007ffdee3d6460 rdi=0x000057d02f54a08d rbp=0x00007ffdee3d6570 rsp=0x00007ffdee3d6458 r8 =0x000000000000000a r9 =0x00000000000000ff r10=0xffffffffffffff88 r11=0x00007a3385a038e0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f549110
0x57d02f549110	'test_c'!0x1110	endbr64	                              	
0x57d02f549114	'test_c'!0x1114	jmp   	qword ptr [rip + 0x2e86]      	mem=0x010000007a338593
0x7a3385860100	'libc.so.6'!0x60100	printf
0x57d02f549404	'test_c'!0x1404	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f549409	'test_c'!0x1409	call  	0xfffffffffffffead            	rax=0x0000000000000000 rbx=0x00007ffdee3d6698 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x000057d02fe942a0 rdi=0x00007ffdee3d6280 rbp=0x00007ffdee3d6570 rsp=0x00007ffdee3d6458 r8 =0x0000000000000073 r9 =0x0000000000000000 r10=0x00000000ffffffff r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f5492b5
0x57d02f5492b5	'test_c'!0x12b5	endbr64	                              	
0x57d02f5492b9	'test_c'!0x12b9	push  	rbp                           	rbp=0x00007ffdee3d6570
0x57d02f5492ba	'test_c'!0x12ba	mov   	rbp, rsp                      	rbp=0x00007ffdee3d6450
0x57d02f5492bd	'test_c'!0x12bd	sub   	rsp, 0x420                    	rsp=0x00007ffdee3d6030 ZF=0x0
0x57d02f5492c4	'test_c'!0x12c4	mov   	rax, qword ptr fs:[0x28]      	rax=0x6c4e721c27e83400
0x57d02f5492cd	'test_c'!0x12cd	mov   	qword ptr [rbp - 8], rax      	mem=0x6c4e721c27e83400
0x57d02f5492d1	'test_c'!0x12d1	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1
0x57d02f5492d3	'test_c'!0x12d3	lea   	rax, [rip + 0xd41]            	rax=0x000057d02f54a01b
0x57d02f5492da	'test_c'!0x12da	mov   	rsi, rax                      	rsi=0x000057d02f54a01b
0x57d02f5492dd	'test_c'!0x12dd	lea   	rax, [rip + 0xd39]            	rax=0x000057d02f54a01d
0x57d02f5492e4	'test_c'!0x12e4	mov   	rdi, rax                      	rdi=0x000057d02f54a01d
0x57d02f5492e7	'test_c'!0x12e7	call  	0xfffffffffffffe5a            	rax=0x000057d02f54a01d rbx=0x00007ffdee3d6698 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x000057d02f54a01b rdi=0x000057d02f54a01d rbp=0x00007ffdee3d6450 rsp=0x00007ffdee3d6028 r8 =0x0000000000000073 r9 =0x0000000000000000 r10=0x00000000ffffffff r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f549140
0x57d02f549140	'test_c'!0x1140	endbr64	                              	
0x57d02f549144	'test_c'!0x1144	jmp   	qword ptr [rip + 0x2e6e]      	mem=0x5e6000007a338592
0x7a3385885e60	'libc.so.6'!0x85e60	_IO_fopen
0x57d02f5492ec	'test_c'!0x12ec	mov   	qword ptr [rbp - 0x418], rax  	mem=0x000057d02fe956c0
0x57d02f5492f3	'test_c'!0x12f3	cmp   	qword ptr [rbp - 0x418], 0    	mem=0x000057d02fe956c0 ZF=0x0
0x57d02f5492fb	'test_c'!0x12fb	jne   	0x2d                          	
0x57d02f549327	'test_c'!0x1327	mov   	rdx, qword ptr [rbp - 0x418]  	rdx=0x000057d02fe956c0
0x57d02f54932e	'test_c'!0x132e	lea   	rax, [rbp - 0x410]            	rax=0x00007ffdee3d6040
0x57d02f549335	'test_c'!0x1335	mov   	esi, 0x400                    	esi=0x0000000000000400
0x57d02f54933a	'test_c'!0x133a	mov   	rdi, rax                      	rdi=0x00007ffdee3d6040
0x57d02f54933d	'test_c'!0x133d	call  	0xfffffffffffffde4            	rax=0x00007ffdee3d6040 rbx=0x00007ffdee3d6698 rcx=0x00007a338591b175 rdx=0x000057d02fe956c0 rsi=0x0000000000000400 rdi=0x00007ffdee3d6040 rbp=0x00007ffdee3d6450 rsp=0x00007ffdee3d6028 r8 =0x0000000000000008 r9 =0x0000000000000001 r10=0x0000000000000000 r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f549120
0x57d02f549120	'test_c'!0x1120	endbr64	                              	
0x57d02f549124	'test_c'!0x1124	jmp   	qword ptr [rip + 0x2e7e]      	mem=0x5b3000007a338586
0x7a3385885b30	'libc.so.6'!0x85b30	_IO_fgets
0x57d02f549342	'test_c'!0x1342	mov   	rax, qword ptr [rbp - 0x418]  	rax=0x000057d02fe956c0
0x57d02f549349	'test_c'!0x1349	mov   	rdi, rax                      	rdi=0x000057d02fe956c0
0x57d02f54934c	'test_c'!0x134c	call  	0xfffffffffffffda5            	rax=0x000057d02fe956c0 rbx=0x00007ffdee3d6698 rcx=0x00000000d016a75f rdx=0x00000000fbad2488 rsi=0x000057d02fe958a1 rdi=0x000057d02fe956c0 rbp=0x00007ffdee3d6450 rsp=0x00007ffdee3d6028 r8 =0x000057d02fe9590d r9 =0x0000000000000410 r10=0x0000000000000001 r11=0x0000000000000346 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f5490f0
0x57d02f5490f0	'test_c'!0x10f0	endbr64	                              	
0x57d02f5490f4	'test_c'!0x10f4	jmp   	qword ptr [rip + 0x2e96]      	mem=0x529000007a338588
0x7a3385885290	'libc.so.6'!0x85290	fclose
0x57d02f549351	'test_c'!0x1351	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f549356	'test_c'!0x1356	mov   	rdx, qword ptr [rbp - 8]      	rdx=0x6c4e721c27e83400
0x57d02f54935a	'test_c'!0x135a	sub   	rdx, qword ptr fs:[0x28]      	rdx=0x0000000000000000 ZF=0x1 PF=0x1
0x57d02f549363	'test_c'!0x1363	je    	8                             	
0x57d02f54936a	'test_c'!0x136a	leave 	                              	
0x57d02f54936b	'test_c'!0x136b	ret   	                              	
0x57d02f54940e	'test_c'!0x140e	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f549413	'test_c'!0x1413	call  	0xfffffffffffffe57            	rax=0x0000000000000000 rbx=0x00007ffdee3d6698 rcx=0x0000000000000001 rdx=0x0000000000000000 rsi=0x000057d02fe956b0 rdi=0x0000000000000000 rbp=0x00007ffdee3d6570 rsp=0x00007ffdee3d6458 r8 =0x000057d02fe94010 r9 =0x0000000000000007 r10=0x000057d02fe956c0 r11=0x603626843f51b8d0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f549269
0x57d02f549269	'test_c'!0x1269	endbr64	                              	
0x57d02f54926d	'test_c'!0x126d	push  	rbp                           	rbp=0x00007ffdee3d6570
0x57d02f54926e	'test_c'!0x126e	mov   	rbp, rsp                      	rbp=0x00007ffdee3d6450
0x57d02f549271	'test_c'!0x1271	mov   	ecx, 0                        	ecx=0x0000000000000000
0x57d02f549276	'test_c'!0x1276	mov   	edx, 0                        	edx=0x0000000000000000
0x57d02f54927b	'test_c'!0x127b	mov   	esi, 0                        	esi=0x0000000000000000
0x57d02f549280	'test_c'!0x1280	mov   	edi, 0                        	edi=0x0000000000000000
0x57d02f549285	'test_c'!0x1285	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f54928a	'test_c'!0x128a	call  	0xfffffffffffffea7            	rax=0x0000000000000000 rbx=0x00007ffdee3d6698 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x0000000000000000 rdi=0x0000000000000000 rbp=0x00007ffdee3d6450 rsp=0x00007ffdee3d6448 r8 =0x000057d02fe94010 r9 =0x0000000000000007 r10=0x000057d02fe956c0 r11=0x603626843f51b8d0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000057d02f54bd78 r15=0x00007a3385b01000 rip=0x000057d02f549130
0x57d02f549130	'test_c'!0x1130	endbr64	                              	
0x57d02f549134	'test_c'!0x1134	jmp   	qword ptr [rip + 0x2e76]      	mem=0x60a000007a338588
0x7a33859260a0	'libc.so.6'!0x1260a0	ptrace
0x57d02f54928f	'test_c'!0x128f	cmp   	rax, -1                       	rax=0x0000000000000000 ZF=0x0 CF=0x1 PF=0x0 AF=0x1
0x57d02f549293	'test_c'!0x1293	jne   	0x1c                          	
0x57d02f5492ae	'test_c'!0x12ae	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f5492b3	'test_c'!0x12b3	pop   	rbp                           	rbp=0x00007ffdee3d6570
0x57d02f5492b4	'test_c'!0x12b4	ret   	                              	
0x57d02f549418	'test_c'!0x1418	mov   	eax, 0                        	eax=0x0000000000000000
0x57d02f54941d	'test_c'!0x141d	mov   	rdx, qword ptr [rbp - 8]      	rdx=0x6c4e721c27e83400
0x57d02f549421	'test_c'!0x1421	sub   	rdx, qword ptr fs:[0x28]      	rdx=0x0000000000000000 ZF=0x1 CF=0x0 PF=0x1 AF=0x0
0x57d02f54942a	'test_c'!0x142a	je    	8                             	
0x57d02f549431	'test_c'!0x1431	leave 	                              	
0x57d02f549432	'test_c'!0x1432	ret   	                              	
0x7a338582a1ca	'libc.so.6'!0x2a1ca	unknown_lib_function(libc.so.6)
0x57d02f549220	'test_c'!0x1220	endbr64	                              	
0x57d02f549224	'test_c'!0x1224	cmp   	byte ptr [rip + 0x2dfd], 0    	mem=0x0000007a3385a044 ZF=0x1 PF=0x1
0x57d02f54922b	'test_c'!0x122b	jne   	0x2e                          	
0x57d02f54922d	'test_c'!0x122d	push  	rbp                           	rbp=0x00007ffdee3d6480
0x57d02f54922e	'test_c'!0x122e	cmp   	qword ptr [rip + 0x2dc2], 0   	mem=0x0000000000000000 ZF=0x0
0x57d02f549236	'test_c'!0x1236	mov   	rbp, rsp                      	rbp=0x00007ffdee3d6450
0x57d02f549239	'test_c'!0x1239	je    	0xf                           	
0x57d02f54923b	'test_c'!0x123b	mov   	rdi, qword ptr [rip + 0x2dc6] 	rdi=0x000057d02f54c008
0x57d02f549242	'test_c'!0x1242	call  	0xfffffffffffffe8f            	rax=0x0000000000000001 rbx=0x000057d02f54bd78 rcx=0x00007ffdee3d63c0 rdx=0x0000000000000000 rsi=0x0000000000000004 rdi=0x000057d02f54c008 rbp=0x00007ffdee3d6450 rsp=0x00007ffdee3d6448 r8 =0x00007ffdee3d6490 r9 =0x0000000000000000 r10=0x00007ffdee3d643f r11=0x00007ffdee3d6440 r12=0x00007a3385b022e0 r13=0x000057d02f54bd78 r14=0x0000000000000000 r15=0x00007a3385b022e0 rip=0x000057d02f5490d0
0x57d02f5490d0	'test_c'!0x10d0	endbr64	                              	
0x57d02f5490d4	'test_c'!0x10d4	jmp   	qword ptr [rip + 0x2f1e]      	mem=0x72c0000000000000
0x7a33858472c0	'libc.so.6'!0x472c0	__cxa_finalize
0x57d02f549247	'test_c'!0x1247	call  	0xffffffffffffff6a            	rax=0x0000000000000001 rbx=0x000057d02f54bd78 rcx=0x0000000000000000 rdx=0x0000000000000001 rsi=0x0000000000000000 rdi=0x000057d02f54c008 rbp=0x00007ffdee3d6450 rsp=0x00007ffdee3d6448 r8 =0x00007ffdee3d6490 r9 =0x0000000000000000 r10=0x00007ffdee3d643f r11=0x00007ffdee3d6440 r12=0x00007a3385b022e0 r13=0x000057d02f54bd78 r14=0x0000000000000000 r15=0x00007a3385b022e0 rip=0x000057d02f5491b0
0x57d02f5491b0	'test_c'!0x11b0	lea   	rdi, [rip + 0x2e59]           	rdi=0x000057d02f54c010
0x57d02f5491b7	'test_c'!0x11b7	lea   	rax, [rip + 0x2e52]           	rax=0x000057d02f54c010
0x57d02f5491be	'test_c'!0x11be	cmp   	rax, rdi                      	rax=0x000057d02f54c010 ZF=0x1
0x57d02f5491c1	'test_c'!0x11c1	je    	0x18                          	
0x57d02f5491d8	'test_c'!0x11d8	ret   	                              	
0x57d02f54924c	'test_c'!0x124c	mov   	byte ptr [rip + 0x2dd5], 1    	mem=0x0100007a3385a044
0x57d02f549253	'test_c'!0x1253	pop   	rbp                           	rbp=0x00007ffdee3d6480
0x57d02f549254	'test_c'!0x1254	ret   	                              	
0x7a3385aca0f2	'ld-linux-x86-64.so.2'!0x10f2	unknown_lib_function(ld-linux-x86-64.so.2)
0x57d02f549434	'test_c'!0x1434	endbr64	                              	
0x57d02f549438	'test_c'!0x1438	sub   	rsp, 8                        	rsp=0x00007ffdee3d6480
0x57d02f54943c	'test_c'!0x143c	add   	rsp, 8                        	rsp=0x00007ffdee3d6488 PF=0x1
0x57d02f549440	'test_c'!0x1440	ret   	                              	
0x7a3385ace578	'ld-linux-x86-64.so.2'!0x5578	unknown_lib_function(ld-linux-x86-64.so.2)
0x7a3385847a76	'libc.so.6'!0x47a76	unknown_lib_function(libc.so.6)
