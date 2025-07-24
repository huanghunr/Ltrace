rax      0x0000000000000038    rbx      0x0000000000000000    rcx      0x00007ffe7c92f188
rdx      0x0000793e25803380    rdi      0x0000793e258372e0    rsi      0x0000793e258378b8
r8       0x0000793e25203b20    r9       0x0000000000000000    r10      0x0000000000000001
r11      0x0000000000000003    r12      0x000059bb74252240    r13      0x00007ffe7c92f170
r14      0x0000000000000000    r15      0x0000000000000000    rbp      0x0000000000000000
rsp      0x00007ffe7c92f170    rip      0x000059bb74252240    eflags   0x0000000000010202
cs       0x0000000000000033    ss       0x000000000000002b    ds       0x0000000000000000
es       0x0000000000000000    fs       0x0000000000000000    gs       0x0000000000000000
fs_base  0x0000793e256d5740    gs_base  0x0000000000000000
ZF=0x0 SF=0x0 CF=0x0 OF=0x0 PF=0x0 AF=0x0
mm0=0x0    st0=0.0    mm1=0x0    st1=0.0    mm2=0x0    st2=0.0    mm3=0x0    st3=0.0    mm4=0x0    st4=0.0    mm5=0x0    st5=0.0    mm6=0x0    st6=0.0    mm7=0x0    st7=0.0    xmm0=0x3e80000000000000000    ymm0=0x3e80000000000000000    xmm1=0x3e80000000000000100    ymm1=0x3e80000000000000100    xmm2=0x793e256743980000793e25674370    ymm2=0x793e256743980000793e25674370    xmm3=0x793e256743980000793e25674370    ymm3=0x793e256743980000793e25674370    xmm4=0x793e256743380000793e25674310    ymm4=0x793e256743380000793e25674310    xmm5=0x793e256743380000793e25674310    ymm5=0x793e256743380000793e25674310    xmm6=0x793e25674398    ymm6=0x793e25674398    xmm7=0x793e256743980000793e25674370    ymm7=0x793e256743980000793e25674370    xmm8=0x0    ymm8=0x0    xmm9=0x0    ymm9=0x0    xmm10=0x0    ymm10=0x0    xmm11=0x0    ymm11=0x0    xmm12=0x0    ymm12=0x0    xmm13=0x0    ymm13=0x0    xmm14=0x0    ymm14=0x0    xmm15=0x0    ymm15=0x0    
-----------
0x59bb74252240	'test1'!0x1240	endbr64	                              	
0x59bb74252244	'test1'!0x1244	xor   	ebp, ebp                      	ebp=0x0000000000000000 ZF=0x1 PF=0x1
0x59bb74252246	'test1'!0x1246	mov   	r9, rdx                       	r9 =0x0000793e25803380
0x59bb74252249	'test1'!0x1249	pop   	rsi                           	rsi=0x0000000000000001
0x59bb7425224a	'test1'!0x124a	mov   	rdx, rsp                      	rdx=0x00007ffe7c92f178
0x59bb7425224d	'test1'!0x124d	and   	rsp, 0xfffffffffffffff0       	rsp=0x00007ffe7c92f170 ZF=0x0 PF=0x0
0x59bb74252251	'test1'!0x1251	push  	rax                           	rax=0x0000000000000038
0x59bb74252252	'test1'!0x1252	push  	rsp                           	rsp=0x00007ffe7c92f160
0x59bb74252253	'test1'!0x1253	xor   	r8d, r8d                      	r8d=0x0000000000000000 ZF=0x1 PF=0x1
0x59bb74252256	'test1'!0x1256	xor   	ecx, ecx                      	ecx=0x0000000000000000
0x59bb74252258	'test1'!0x1258	lea   	rdi, [rip + 0x265]            	rdi=0x000059bb742524c4
0x59bb7425225f	'test1'!0x125f	call  	qword ptr [rip + 0x2d7b]      	rax=0x0000000000000038 rbx=0x0000000000000000 rcx=0x0000000000000000 rdx=0x00007ffe7c92f178 rsi=0x0000000000000001 rdi=0x000059bb742524c4 rbp=0x0000000000000000 rsp=0x00007ffe7c92f158 r8 =0x0000000000000000 r9 =0x0000793e25803380 r10=0x0000000000000001 r11=0x0000000000000003 r12=0x000059bb74252240 r13=0x00007ffe7c92f170 r14=0x0000000000000000 r15=0x0000000000000000 rip=0x0000793e2502a200
0x793e2502a200	'libc.so.6'!0x2a200	__libc_start_main
0x59bb74252000	'test1'!0x1000	endbr64	                              	
0x59bb74252004	'test1'!0x1004	sub   	rsp, 8                        	rsp=0x00007ffe7c92f0f0
0x59bb74252008	'test1'!0x1008	mov   	rax, qword ptr [rip + 0x2fe1] 	rax=0x0000000000000000
0x59bb7425200f	'test1'!0x100f	test  	rax, rax                      	rax=0x0000000000000000 ZF=0x1
0x59bb74252012	'test1'!0x1012	je    	5                             	
0x59bb74252016	'test1'!0x1016	add   	rsp, 8                        	rsp=0x00007ffe7c92f0f8 ZF=0x0 PF=0x0
0x59bb7425201a	'test1'!0x101a	ret   	                              	
0x793e2502a2b4	'libc.so.6'!0x2a2b4	unknown_lib_function(libc.so.6)
0x59bb74252320	'test1'!0x1320	endbr64	                              	
0x59bb74252324	'test1'!0x1324	jmp   	0xffffffffffffff7d            	
0x59bb742522a0	'test1'!0x12a0	lea   	rdi, [rip + 0x2d71]           	rdi=0x000059bb74255018
0x59bb742522a7	'test1'!0x12a7	lea   	rsi, [rip + 0x2d6a]           	rsi=0x000059bb74255018
0x59bb742522ae	'test1'!0x12ae	sub   	rsi, rdi                      	rsi=0x0000000000000000
0x59bb742522b1	'test1'!0x12b1	mov   	rax, rsi                      	rax=0x0000000000000000
0x59bb742522b4	'test1'!0x12b4	shr   	rsi, 0x3f                     	rsi=0x0000000000000000
0x59bb742522b8	'test1'!0x12b8	sar   	rax, 3                        	rax=0x0000000000000000
0x59bb742522bc	'test1'!0x12bc	add   	rsi, rax                      	rsi=0x0000000000000000
0x59bb742522bf	'test1'!0x12bf	sar   	rsi, 1                        	rsi=0x0000000000000000
0x59bb742522c2	'test1'!0x12c2	je    	0x17                          	
0x59bb742522d8	'test1'!0x12d8	ret   	                              	
0x793e2502a304	'libc.so.6'!0x2a304	unknown_lib_function(libc.so.6)
0x59bb742524c4	'test1'!0x14c4	endbr64	                              	
0x59bb742524c8	'test1'!0x14c8	push  	rbp                           	rbp=0x00007ffe7c92f0f0
0x59bb742524c9	'test1'!0x14c9	mov   	rbp, rsp                      	rbp=0x00007ffe7c92f050
0x59bb742524cc	'test1'!0x14cc	push  	rbx                           	rbx=0x00007ffe7c92f178
0x59bb742524cd	'test1'!0x14cd	sub   	rsp, 0x38                     	rsp=0x00007ffe7c92f010 ZF=0x0 PF=0x0
0x59bb742524d1	'test1'!0x14d1	mov   	rax, qword ptr fs:[0x28]      	rax=0x89d18a176a28e700
0x59bb742524da	'test1'!0x14da	mov   	qword ptr [rbp - 0x18], rax   	mem=0x89d18a176a28e700
0x59bb742524de	'test1'!0x14de	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1 PF=0x1
0x59bb742524e0	'test1'!0x14e0	lea   	rax, [rbp - 0x40]             	rax=0x00007ffe7c92f010
0x59bb742524e4	'test1'!0x14e4	mov   	rdi, rax                      	rdi=0x00007ffe7c92f010
0x59bb742524e7	'test1'!0x14e7	call  	0xfffffffffffffd0a            	rax=0x00007ffe7c92f010 rbx=0x00007ffe7c92f178 rcx=0x000059bb74254d20 rdx=0x00007ffe7c92f188 rsi=0x00007ffe7c92f178 rdi=0x00007ffe7c92f010 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000000000000000 r9 =0x0000793e25803380 r10=0x0000000000000001 r11=0x0000000000000003 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521f0
0x59bb742521f0	'test1'!0x11f0	endbr64	                              	
0x59bb742521f4	'test1'!0x11f4	jmp   	qword ptr [rip + 0x2dae]      	mem=0x88700000793e254d
0x793e25568870	'libstdc++.so.6.0.33'!0x168870	_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2Ev
0x59bb742524ec	'test1'!0x14ec	lea   	rax, [rip + 0xb55]            	rax=0x000059bb74253048
0x59bb742524f3	'test1'!0x14f3	mov   	rsi, rax                      	rsi=0x000059bb74253048
0x59bb742524f6	'test1'!0x14f6	lea   	rax, [rip + 0x2b43]           	rax=0x000059bb74255040
0x59bb742524fd	'test1'!0x14fd	mov   	rdi, rax                      	rdi=0x000059bb74255040
0x59bb74252500	'test1'!0x1500	call  	0xfffffffffffffca1            	rax=0x000059bb74255040 rbx=0x00007ffe7c92f178 rcx=0x000059bb74254d20 rdx=0x00007ffe7c92f188 rsi=0x000059bb74253048 rdi=0x000059bb74255040 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000000000000000 r9 =0x0000793e25803380 r10=0x0000000000000001 r11=0x0000000000000003 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521a0
0x59bb742521a0	'test1'!0x11a0	endbr64	                              	
0x59bb742521a4	'test1'!0x11a4	jmp   	qword ptr [rip + 0x2dd6]      	mem=0x71100000793e2556
0x793e25557110	'libstdc++.so.6.0.33'!0x157110	_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
0x59bb74252505	'test1'!0x1505	mov   	rdx, qword ptr [rip + 0x2acc] 	rdx=0x0000793e255569f0
0x59bb7425250c	'test1'!0x150c	mov   	rsi, rdx                      	rsi=0x0000793e255569f0
0x59bb7425250f	'test1'!0x150f	mov   	rdi, rax                      	rdi=0x000059bb74255040
0x59bb74252512	'test1'!0x1512	call  	0xfffffffffffffc9f            	rax=0x000059bb74255040 rbx=0x00007ffe7c92f178 rcx=0x0000000000000000 rdx=0x0000793e255569f0 rsi=0x0000793e255569f0 rdi=0x000059bb74255040 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000793e25203b20 r9 =0x0000000000000410 r10=0x0000000000000001 r11=0x0000000000000002 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521b0
0x59bb742521b0	'test1'!0x11b0	endbr64	                              	
0x59bb742521b4	'test1'!0x11b4	jmp   	qword ptr [rip + 0x2dce]      	mem=0x59c00000793e2555
0x793e255559c0	'libstdc++.so.6.0.33'!0x1559c0	_ZNSolsEPFRSoS_E
0x59bb74252517	'test1'!0x1517	lea   	rax, [rbp - 0x40]             	rax=0x00007ffe7c92f010
0x59bb7425251b	'test1'!0x151b	mov   	rsi, rax                      	rsi=0x00007ffe7c92f010
0x59bb7425251e	'test1'!0x151e	lea   	rax, [rip + 0x2c3b]           	rax=0x000059bb74255160
0x59bb74252525	'test1'!0x1525	mov   	rdi, rax                      	rdi=0x000059bb74255160
0x59bb74252528	'test1'!0x1528	call  	0xfffffffffffffcb9            	rax=0x000059bb74255160 rbx=0x00007ffe7c92f178 rcx=0x0000793e2511c574 rdx=0x0000793e25674310 rsi=0x00007ffe7c92f010 rdi=0x000059bb74255160 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000793e25203b20 r9 =0x0000000000000410 r10=0x0000793e2500edb8 r11=0x0000793e250857f0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521e0
0x59bb742521e0	'test1'!0x11e0	endbr64	                              	
0x59bb742521e4	'test1'!0x11e4	jmp   	qword ptr [rip + 0x2db6]      	mem=0x5d800000793e2504
0x793e254d5d80	'libstdc++.so.6.0.33'!0xd5d80	_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE
0x59bb7425252d	'test1'!0x152d	lea   	rax, [rip + 0xb34]            	rax=0x000059bb74253068
0x59bb74252534	'test1'!0x1534	mov   	rsi, rax                      	rsi=0x000059bb74253068
0x59bb74252537	'test1'!0x1537	lea   	rax, [rip + 0x2b02]           	rax=0x000059bb74255040
0x59bb7425253e	'test1'!0x153e	mov   	rdi, rax                      	rdi=0x000059bb74255040
0x59bb74252541	'test1'!0x1541	call  	0xfffffffffffffc60            	rax=0x000059bb74255040 rbx=0x00007ffe7c92f178 rcx=0x000000000000000f rdx=0x0000793e25673870 rsi=0x000059bb74253068 rdi=0x000059bb74255040 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000793e251b28c0 r9 =0x0000000000000000 r10=0x0000793e25414190 r11=0x000000000000000f r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521a0
0x59bb742521a0	'test1'!0x11a0	endbr64	                              	
0x59bb742521a4	'test1'!0x11a4	jmp   	qword ptr [rip + 0x2dd6]      	mem=0x71100000793e2556
0x793e25557110	'libstdc++.so.6.0.33'!0x157110	_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
0x59bb74252546	'test1'!0x1546	mov   	rdx, rax                      	rdx=0x000059bb74255040
0x59bb74252549	'test1'!0x1549	lea   	rax, [rbp - 0x40]             	rax=0x00007ffe7c92f010
0x59bb7425254d	'test1'!0x154d	mov   	rsi, rax                      	rsi=0x00007ffe7c92f010
0x59bb74252550	'test1'!0x1550	mov   	rdi, rdx                      	rdi=0x000059bb74255040
0x59bb74252553	'test1'!0x1553	call  	0xfffffffffffffc3e            	rax=0x00007ffe7c92f010 rbx=0x00007ffe7c92f178 rcx=0x0000000000000000 rdx=0x000059bb74255040 rsi=0x00007ffe7c92f010 rdi=0x000059bb74255040 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000793e251b28c0 r9 =0x0000000000000000 r10=0x0000793e25414190 r11=0x000000000000000f r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252190
0x59bb74252190	'test1'!0x1190	endbr64	                              	
0x59bb74252194	'test1'!0x1194	jmp   	qword ptr [rip + 0x2dde]      	mem=0xbd400000793e2512
0x793e2556bd40	'libstdc++.so.6.0.33'!0x16bd40	_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE
0x59bb74252558	'test1'!0x1558	mov   	rdx, rax                      	rdx=0x000059bb74255040
0x59bb7425255b	'test1'!0x155b	lea   	rax, [rip + 0xb17]            	rax=0x000059bb74253079
0x59bb74252562	'test1'!0x1562	mov   	rsi, rax                      	rsi=0x000059bb74253079
0x59bb74252565	'test1'!0x1565	mov   	rdi, rdx                      	rdi=0x000059bb74255040
0x59bb74252568	'test1'!0x1568	call  	0xfffffffffffffc39            	rax=0x000059bb74253079 rbx=0x00007ffe7c92f178 rcx=0x0000000000000000 rdx=0x000059bb74255040 rsi=0x000059bb74253079 rdi=0x000059bb74255040 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000793e251b28c0 r9 =0x0000000000000000 r10=0x0000793e25414190 r11=0x000000000000000f r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521a0
0x59bb742521a0	'test1'!0x11a0	endbr64	                              	
0x59bb742521a4	'test1'!0x11a4	jmp   	qword ptr [rip + 0x2dd6]      	mem=0x71100000793e2556
0x793e25557110	'libstdc++.so.6.0.33'!0x157110	_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
0x59bb7425256d	'test1'!0x156d	mov   	rdx, qword ptr [rip + 0x2a64] 	rdx=0x0000793e255569f0
0x59bb74252574	'test1'!0x1574	mov   	rsi, rdx                      	rsi=0x0000793e255569f0
0x59bb74252577	'test1'!0x1577	mov   	rdi, rax                      	rdi=0x000059bb74255040
0x59bb7425257a	'test1'!0x157a	call  	0xfffffffffffffc37            	rax=0x000059bb74255040 rbx=0x00007ffe7c92f178 rcx=0x0000000000000000 rdx=0x0000793e255569f0 rsi=0x0000793e255569f0 rdi=0x000059bb74255040 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000793e251b28c0 r9 =0x0000000000000000 r10=0x0000793e25414190 r11=0x000000000000000f r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521b0
0x59bb742521b0	'test1'!0x11b0	endbr64	                              	
0x59bb742521b4	'test1'!0x11b4	jmp   	qword ptr [rip + 0x2dce]      	mem=0x59c00000793e2555
0x793e255559c0	'libstdc++.so.6.0.33'!0x1559c0	_ZNSolsEPFRSoS_E
0x59bb7425257f	'test1'!0x157f	call  	0xfffffffffffffdfc            	rax=0x000059bb74255040 rbx=0x00007ffe7c92f178 rcx=0x0000793e2511c574 rdx=0x0000793e25674310 rsi=0x0000000000000000 rdi=0x0000793e25205710 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x0000793e251b28c0 r9 =0x0000000000000000 r10=0x0000793e25414190 r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb7425237a
0x59bb7425237a	'test1'!0x137a	endbr64	                              	
0x59bb7425237e	'test1'!0x137e	push  	rbp                           	rbp=0x00007ffe7c92f050
0x59bb7425237f	'test1'!0x137f	mov   	rbp, rsp                      	rbp=0x00007ffe7c92f000
0x59bb74252382	'test1'!0x1382	push  	rbx                           	rbx=0x00007ffe7c92f178
0x59bb74252383	'test1'!0x1383	sub   	rsp, 0x238                    	rsp=0x00007ffe7c92edc0
0x59bb7425238a	'test1'!0x138a	mov   	rax, qword ptr fs:[0x28]      	rax=0x89d18a176a28e700
0x59bb74252393	'test1'!0x1393	mov   	qword ptr [rbp - 0x18], rax   	mem=0x89d18a176a28e700
0x59bb74252397	'test1'!0x1397	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1
0x59bb74252399	'test1'!0x1399	lea   	rax, [rbp - 0x220]            	rax=0x00007ffe7c92ede0
0x59bb742523a0	'test1'!0x13a0	mov   	edx, 8                        	edx=0x0000000000000008
0x59bb742523a5	'test1'!0x13a5	lea   	rcx, [rip + 0xc6f]            	rcx=0x000059bb7425301b
0x59bb742523ac	'test1'!0x13ac	mov   	rsi, rcx                      	rsi=0x000059bb7425301b
0x59bb742523af	'test1'!0x13af	mov   	rdi, rax                      	rdi=0x00007ffe7c92ede0
0x59bb742523b2	'test1'!0x13b2	call  	0xfffffffffffffe7f            	rax=0x00007ffe7c92ede0 rbx=0x00007ffe7c92f178 rcx=0x000059bb7425301b rdx=0x0000000000000008 rsi=0x000059bb7425301b rdi=0x00007ffe7c92ede0 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92edb8 r8 =0x0000793e251b28c0 r9 =0x0000000000000000 r10=0x0000793e25414190 r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252230
0x59bb74252230	'test1'!0x1230	endbr64	                              	
0x59bb74252234	'test1'!0x1234	jmp   	qword ptr [rip + 0x2d8e]      	mem=0xfbf00000793e257e
0x793e2552fbf0	'libstdc++.so.6.0.33'!0x12fbf0	_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode
0x59bb742523b7	'test1'!0x13b7	lea   	rax, [rbp - 0x220]            	rax=0x00007ffe7c92ede0
0x59bb742523be	'test1'!0x13be	mov   	rdi, rax                      	rdi=0x00007ffe7c92ede0
0x59bb742523c1	'test1'!0x13c1	call  	0xfffffffffffffe50            	rax=0x00007ffe7c92ede0 rbx=0x00007ffe7c92f178 rcx=0x000059bb809178b0 rdx=0x0000793e25672dc0 rsi=0x0000000000000000 rdi=0x00007ffe7c92ede0 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92edb8 r8 =0x0000793e25203b20 r9 =0x0000000000000000 r10=0x0000793e2540f408 r11=0x0000793e25533eb0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252210
0x59bb74252210	'test1'!0x1210	endbr64	                              	
0x59bb74252214	'test1'!0x1214	jmp   	qword ptr [rip + 0x2d9e]      	mem=0xbc900000793e2508
0x793e2552bc90	'libstdc++.so.6.0.33'!0x12bc90	_ZNSt14basic_ifstreamIcSt11char_traitsIcEE7is_openEv
0x59bb742523c6	'test1'!0x13c6	xor   	eax, 1                        	eax=0x000000007c92ed00 PF=0x1
0x59bb742523c9	'test1'!0x13c9	test  	al, al                        	al =0x0000000000000000 ZF=0x1
0x59bb742523cb	'test1'!0x13cb	je    	0x35                          	
0x59bb742523ff	'test1'!0x13ff	lea   	rax, [rbp - 0x240]            	rax=0x00007ffe7c92edc0
0x59bb74252406	'test1'!0x1406	mov   	rdi, rax                      	rdi=0x00007ffe7c92edc0
0x59bb74252409	'test1'!0x1409	call  	0xfffffffffffffde8            	rax=0x00007ffe7c92edc0 rbx=0x00007ffe7c92f178 rcx=0x000059bb809178b0 rdx=0x0000793e25672dc0 rsi=0x0000000000000000 rdi=0x00007ffe7c92edc0 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92edb8 r8 =0x0000793e25203b20 r9 =0x0000000000000000 r10=0x0000793e2540f408 r11=0x0000793e25533eb0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521f0
0x59bb742521f0	'test1'!0x11f0	endbr64	                              	
0x59bb742521f4	'test1'!0x11f4	jmp   	qword ptr [rip + 0x2dae]      	mem=0x88700000793e254d
0x793e25568870	'libstdc++.so.6.0.33'!0x168870	_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2Ev
0x59bb7425240e	'test1'!0x140e	lea   	rdx, [rbp - 0x240]            	rdx=0x00007ffe7c92edc0
0x59bb74252415	'test1'!0x1415	lea   	rax, [rbp - 0x220]            	rax=0x00007ffe7c92ede0
0x59bb7425241c	'test1'!0x141c	mov   	rsi, rdx                      	rsi=0x00007ffe7c92edc0
0x59bb7425241f	'test1'!0x141f	mov   	rdi, rax                      	rdi=0x00007ffe7c92ede0
0x59bb74252422	'test1'!0x1422	call  	0xfffffffffffffd1f            	rax=0x00007ffe7c92ede0 rbx=0x00007ffe7c92f178 rcx=0x000059bb809178b0 rdx=0x00007ffe7c92edc0 rsi=0x00007ffe7c92edc0 rdi=0x00007ffe7c92ede0 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92edb8 r8 =0x0000793e25203b20 r9 =0x0000000000000000 r10=0x0000793e2540f408 r11=0x0000793e25533eb0 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252140
0x59bb74252140	'test1'!0x1140	endbr64	                              	
0x59bb74252144	'test1'!0x1144	jmp   	qword ptr [rip + 0x2e06]      	mem=0xbd50000000000000
0x793e2556bd50	'libstdc++.so.6.0.33'!0x16bd50	_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE
0x59bb74252427	'test1'!0x1427	lea   	rax, [rbp - 0x220]            	rax=0x00007ffe7c92ede0
0x59bb7425242e	'test1'!0x142e	mov   	rdi, rax                      	rdi=0x00007ffe7c92ede0
0x59bb74252431	'test1'!0x1431	call  	0xfffffffffffffd20            	rax=0x00007ffe7c92ede0 rbx=0x00007ffe7c92f178 rcx=0x000059bb80917930 rdx=0x000000000000006b rsi=0x3ffffffffffffffe rdi=0x00007ffe7c92ede0 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92edb8 r8 =0x0000793e25203b20 r9 =0x0000000000000080 r10=0x0000793e25019ee8 r11=0x0000793e25188a00 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252150
0x59bb74252150	'test1'!0x1150	endbr64	                              	
0x59bb74252154	'test1'!0x1154	jmp   	qword ptr [rip + 0x2dfe]      	mem=0x01a00000793e2556
0x793e255301a0	'libstdc++.so.6.0.33'!0x1301a0	_ZNSt14basic_ifstreamIcSt11char_traitsIcEE5closeEv
0x59bb74252436	'test1'!0x1436	mov   	ebx, 0                        	ebx=0x0000000000000000
0x59bb7425243b	'test1'!0x143b	lea   	rax, [rbp - 0x240]            	rax=0x00007ffe7c92edc0
0x59bb74252442	'test1'!0x1442	mov   	rdi, rax                      	rdi=0x00007ffe7c92edc0
0x59bb74252445	'test1'!0x1445	call  	0xfffffffffffffd2c            	rax=0x00007ffe7c92edc0 rbx=0x0000000000000000 rcx=0x0000000000000001 rdx=0x000000059bb80915 rsi=0x000059bb809156c0 rdi=0x00007ffe7c92edc0 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92edb8 r8 =0x000059bb80902010 r9 =0x0000000000000007 r10=0x000059bb809156d0 r11=0x06f52f9a663547ac r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252170
0x59bb74252170	'test1'!0x1170	endbr64	                              	
0x59bb74252174	'test1'!0x1174	jmp   	qword ptr [rip + 0x2dee]      	mem=0x8ae00000793e2553
0x793e25568ae0	'libstdc++.so.6.0.33'!0x168ae0	_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev
0x59bb7425244a	'test1'!0x144a	lea   	rax, [rbp - 0x220]            	rax=0x00007ffe7c92ede0
0x59bb74252451	'test1'!0x1451	mov   	rdi, rax                      	rdi=0x00007ffe7c92ede0
0x59bb74252454	'test1'!0x1454	call  	0xfffffffffffffd0d            	rax=0x00007ffe7c92ede0 rbx=0x0000000000000000 rcx=0x0000000000000001 rdx=0x000000059bb80917 rsi=0x000059bb809178b0 rdi=0x00007ffe7c92ede0 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92edb8 r8 =0x000059bb80902010 r9 =0x0000000000000007 r10=0x000059bb809178c0 r11=0x06f52f9a663547ac r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252160
0x59bb74252160	'test1'!0x1160	endbr64	                              	
0x59bb74252164	'test1'!0x1164	jmp   	qword ptr [rip + 0x2df6]      	mem=0x05f00000793e2553
0x793e255305f0	'libstdc++.so.6.0.33'!0x1305f0	_ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev
0x59bb74252459	'test1'!0x1459	mov   	eax, ebx                      	eax=0x0000000000000000
0x59bb7425245b	'test1'!0x145b	mov   	rdx, qword ptr [rbp - 0x18]   	rdx=0x89d18a176a28e700
0x59bb7425245f	'test1'!0x145f	sub   	rdx, qword ptr fs:[0x28]      	rdx=0x0000000000000000
0x59bb74252468	'test1'!0x1468	je    	0x57                          	
0x59bb742524be	'test1'!0x14be	mov   	rbx, qword ptr [rbp - 8]      	rbx=0x00007ffe7c92f178
0x59bb742524c2	'test1'!0x14c2	leave 	                              	
0x59bb742524c3	'test1'!0x14c3	ret   	                              	
0x59bb74252584	'test1'!0x1584	call  	0xfffffffffffffda6            	rax=0x0000000000000000 rbx=0x00007ffe7c92f178 rcx=0x0000000000000001 rdx=0x0000000000000000 rsi=0x0000000000000000 rdi=0x00007ffe7c92efb0 rbp=0x00007ffe7c92f050 rsp=0x00007ffe7c92f008 r8 =0x000059bb80902010 r9 =0x0000000000000007 r10=0x0000793e25423da8 r11=0x0000793e254e8470 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252329
0x59bb74252329	'test1'!0x1329	endbr64	                              	
0x59bb7425232d	'test1'!0x132d	push  	rbp                           	rbp=0x00007ffe7c92f050
0x59bb7425232e	'test1'!0x132e	mov   	rbp, rsp                      	rbp=0x00007ffe7c92f000
0x59bb74252331	'test1'!0x1331	mov   	ecx, 0                        	ecx=0x0000000000000000
0x59bb74252336	'test1'!0x1336	mov   	edx, 0                        	edx=0x0000000000000000
0x59bb7425233b	'test1'!0x133b	mov   	esi, 0                        	esi=0x0000000000000000
0x59bb74252340	'test1'!0x1340	mov   	edi, 0                        	edi=0x0000000000000000
0x59bb74252345	'test1'!0x1345	mov   	eax, 0                        	eax=0x0000000000000000
0x59bb7425234a	'test1'!0x134a	call  	0xfffffffffffffe37            	rax=0x0000000000000000 rbx=0x00007ffe7c92f178 rcx=0x0000000000000000 rdx=0x0000000000000000 rsi=0x0000000000000000 rdi=0x0000000000000000 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92eff8 r8 =0x000059bb80902010 r9 =0x0000000000000007 r10=0x0000793e25423da8 r11=0x0000793e254e8470 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252180
0x59bb74252180	'test1'!0x1180	endbr64	                              	
0x59bb74252184	'test1'!0x1184	jmp   	qword ptr [rip + 0x2de6]      	mem=0x60a00000793e2556
0x793e251260a0	'libc.so.6'!0x1260a0	ptrace
0x59bb7425234f	'test1'!0x134f	cmp   	rax, -1                       	rax=0xffffffffffffffff
0x59bb74252353	'test1'!0x1353	sete  	al                            	al =0x0000000000000001
0x59bb74252356	'test1'!0x1356	test  	al, al                        	al =0x0000000000000001 ZF=0x0 PF=0x0
0x59bb74252358	'test1'!0x1358	je    	0x1c                          	
0x59bb7425235a	'test1'!0x135a	lea   	rax, [rip + 0xca7]            	rax=0x000059bb74253008
0x59bb74252361	'test1'!0x1361	mov   	rdi, rax                      	rdi=0x000059bb74253008
0x59bb74252364	'test1'!0x1364	call  	0xfffffffffffffe9d            	rax=0x000059bb74253008 rbx=0x00007ffe7c92f178 rcx=0x0000793e251260fd rdx=0x0000000000000000 rsi=0x0000000000000000 rdi=0x000059bb74253008 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92eff8 r8 =0x00000000ffffffff r9 =0x0000000000000007 r10=0x0000000000000000 r11=0x0000000000000386 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb74252200
0x59bb74252200	'test1'!0x1200	endbr64	                              	
0x59bb74252204	'test1'!0x1204	jmp   	qword ptr [rip + 0x2da6]      	mem=0x7be00000793e2556
0x793e25087be0	'libc.so.6'!0x87be0	_IO_puts
0x59bb74252369	'test1'!0x1369	mov   	edi, 1                        	edi=0x0000000000000001
0x59bb7425236e	'test1'!0x136e	call  	0xfffffffffffffe63            	rax=0x0000000000000013 rbx=0x00007ffe7c92f178 rcx=0x0000793e2511c574 rdx=0x0000000000000000 rsi=0x000059bb809142b0 rdi=0x0000000000000001 rbp=0x00007ffe7c92f000 rsp=0x00007ffe7c92eff8 r8 =0x00000000ffffffff r9 =0x0000000000000007 r10=0x0000000000000000 r11=0x0000000000000302 r12=0x0000000000000001 r13=0x0000000000000000 r14=0x000059bb74254d20 r15=0x0000793e25836000 rip=0x000059bb742521d0
0x59bb742521d0	'test1'!0x11d0	endbr64	                              	
0x59bb742521d4	'test1'!0x11d4	jmp   	qword ptr [rip + 0x2dbe]      	mem=0x7ba00000793e2513
0x793e25047ba0	'libc.so.6'!0x47ba0	exit  
0x59bb742522e0	'test1'!0x12e0	endbr64	                              	
0x59bb742522e4	'test1'!0x12e4	cmp   	byte ptr [rip + 0x30a5], 0    	mem=0x000000793e2567b9 ZF=0x1 PF=0x1
0x59bb742522eb	'test1'!0x12eb	jne   	0x2e                          	
0x59bb742522ed	'test1'!0x12ed	push  	rbp                           	rbp=0x00007ffe7c92eee0
0x59bb742522ee	'test1'!0x12ee	cmp   	qword ptr [rip + 0x2cda], 0   	mem=0x0000793e2552fbf0 ZF=0x0
0x59bb742522f6	'test1'!0x12f6	mov   	rbp, rsp                      	rbp=0x00007ffe7c92eeb0
0x59bb742522f9	'test1'!0x12f9	je    	0xf                           	
0x59bb742522fb	'test1'!0x12fb	mov   	rdi, qword ptr [rip + 0x2d06] 	rdi=0x000059bb74255008
0x59bb74252302	'test1'!0x1302	call  	0xfffffffffffffe2f            	rax=0x0000000000000001 rbx=0x000059bb74254d20 rcx=0x00007ffe7c92ee00 rdx=0x0000000000000000 rsi=0x0000000000000007 rdi=0x000059bb74255008 rbp=0x00007ffe7c92eeb0 rsp=0x00007ffe7c92eea8 r8 =0x00007ffe7c92eef0 r9 =0x0000000000000000 r10=0x00007ffe7c92ee9f r11=0x00007ffe7c92eea0 r12=0x0000793e258372e0 r13=0x000059bb74254d20 r14=0x0000000000000000 r15=0x0000793e258372e0 rip=0x000059bb74252130
0x59bb74252130	'test1'!0x1130	endbr64	                              	
0x59bb74252134	'test1'!0x1134	jmp   	qword ptr [rip + 0x2e96]      	mem=0x72c00000793e2552
0x793e250472c0	'libc.so.6'!0x472c0	__cxa_finalize
0x59bb74252307	'test1'!0x1307	call  	0xffffffffffffff6a            	rax=0x0000000000000001 rbx=0x000059bb74254d20 rcx=0x0000000000000000 rdx=0x0000000000000001 rsi=0x0000000000000000 rdi=0x000059bb74255008 rbp=0x00007ffe7c92eeb0 rsp=0x00007ffe7c92eea8 r8 =0x00007ffe7c92eef0 r9 =0x0000000000000000 r10=0x00007ffe7c92ee9f r11=0x00007ffe7c92eea0 r12=0x0000793e258372e0 r13=0x000059bb74254d20 r14=0x0000000000000000 r15=0x0000793e258372e0 rip=0x000059bb74252270
0x59bb74252270	'test1'!0x1270	lea   	rdi, [rip + 0x2da1]           	rdi=0x000059bb74255018
0x59bb74252277	'test1'!0x1277	lea   	rax, [rip + 0x2d9a]           	rax=0x000059bb74255018
0x59bb7425227e	'test1'!0x127e	cmp   	rax, rdi                      	rax=0x000059bb74255018 ZF=0x1
0x59bb74252281	'test1'!0x1281	je    	0x18                          	
0x59bb74252298	'test1'!0x1298	ret   	                              	
0x59bb7425230c	'test1'!0x130c	mov   	byte ptr [rip + 0x307d], 1    	mem=0x010000793e2567b9
0x59bb74252313	'test1'!0x1313	pop   	rbp                           	rbp=0x00007ffe7c92eee0
0x59bb74252314	'test1'!0x1314	ret   	                              	
0x793e257ff0f2	'ld-linux-x86-64.so.2'!0x10f2	unknown_lib_function(ld-linux-x86-64.so.2)
0x59bb742525ec	'test1'!0x15ec	endbr64	                              	
0x59bb742525f0	'test1'!0x15f0	sub   	rsp, 8                        	rsp=0x00007ffe7c92eee0
0x59bb742525f4	'test1'!0x15f4	add   	rsp, 8                        	rsp=0x00007ffe7c92eee8 PF=0x1
0x59bb742525f8	'test1'!0x15f8	ret   	                              	
0x793e25803578	'ld-linux-x86-64.so.2'!0x5578	unknown_lib_function(ld-linux-x86-64.so.2)
0x793e254b7aa0	'libstdc++.so.6.0.33'!0xb7aa0	unknown_lib_function(libstdc++.so.6.0.33)
