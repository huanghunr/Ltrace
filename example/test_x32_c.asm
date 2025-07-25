eax      0xf7fe7a20    ebx      0xf7fe6fe8    ecx      0xf7fe7d28
edx      0xf7fb7e80    esi      0xffdeccbc    edi      0x5663e0f0
ebp      0x00000000    esp      0xffdeccb0    eip      0x5663e0f0
eflags   0x00010282    cs       0x00000023    ss       0x0000002b
ds       0x0000002b    es       0x0000002b    fs       0x00000000
gs       0x00000063
ZF=0x0 SF=0x1 CF=0x0 OF=0x0 PF=0x0 AF=0x0
mm0=0x0    st0=0.0    mm1=0x0    st1=0.0    mm2=0x0    st2=0.0    mm3=0x0    st3=0.0    mm4=0x0    st4=0.0    mm5=0x0    st5=0.0    mm6=0x0    st6=0.0    mm7=0x0    st7=0.0    
xmm0=0x0    ymm0=0x0    xmm1=0x0    ymm1=0x0    xmm2=0x0    ymm2=0x0    xmm3=0x0    ymm3=0x0    xmm4=0x0    ymm4=0x0    xmm5=0x0    ymm5=0x0    xmm6=0x0    ymm6=0x0    xmm7=0x0    ymm7=0x0    
-----------
0x5663e0f0	'test_x32_c'!0x10f0	xor   	ebp, ebp                      	ebp=0x00000000 SF=0x0 ZF=0x1 PF=0x1
0x5663e0f2	'test_x32_c'!0x10f2	pop   	esi                           	esi=0x00000001
0x5663e0f3	'test_x32_c'!0x10f3	mov   	ecx, esp                      	ecx=0xffdeccb4
0x5663e0f5	'test_x32_c'!0x10f5	and   	esp, 0xfffffff0               	esp=0xffdeccb0 SF=0x1 ZF=0x0 PF=0x0
0x5663e0f8	'test_x32_c'!0x10f8	push  	eax                           	eax=0xf7fe7a20
0x5663e0f9	'test_x32_c'!0x10f9	push  	esp                           	esp=0xffdecca8
0x5663e0fa	'test_x32_c'!0x10fa	push  	edx                           	edx=0xf7fb7e80
0x5663e0fb	'test_x32_c'!0x10fb	call  	0x1e                          	eax=0xf7fe7a20 ebx=0xf7fe6fe8 ecx=0xffdeccb4 edx=0xf7fb7e80 esi=0x00000001 edi=0x5663e0f0 ebp=0x00000000 esp=0xffdecca0
0x5663e118	'test_x32_c'!0x1118	mov   	ebx, dword ptr [esp]          	ebx=0x5663e100
0x5663e11b	'test_x32_c'!0x111b	ret   	                              	
0x5663e100	'test_x32_c'!0x1100	add   	ebx, 0x2eb0                   	ebx=0x56640fb0 SF=0x0
0x5663e106	'test_x32_c'!0x1106	push  	0                             	
0x5663e108	'test_x32_c'!0x1108	push  	0                             	
0x5663e10a	'test_x32_c'!0x110a	push  	ecx                           	ecx=0xffdeccb4
0x5663e10b	'test_x32_c'!0x110b	push  	esi                           	esi=0x00000001
0x5663e10c	'test_x32_c'!0x110c	push  	dword ptr [ebx + 0x48]        	mem=0x5663e31e
0x5663e112	'test_x32_c'!0x1112	call  	0xffffff1f                    	eax=0xf7fe7a20 ebx=0x56640fb0 ecx=0xffdeccb4 edx=0xf7fb7e80 esi=0x00000001 edi=0x5663e0f0 ebp=0x00000000 esp=0xffdecc8c
0x5663e030	'test_x32_c'!0x1030	jmp   	dword ptr [ebx + 0xc]         	mem=0xf7d87cf0
0xf7d87cf0	'libc.so.6'!__libc_start_main
0x5663e000	'test_x32_c'!0x1000	push  	ebx                           	ebx=0xf7f93e34
0x5663e001	'test_x32_c'!0x1001	sub   	esp, 8                        	esp=0xffdecc40 SF=0x1 PF=0x0
0x5663e004	'test_x32_c'!0x1004	call  	0x11d                         	eax=0xffdeccbc ebx=0xf7f93e34 ecx=0x5663e000 edx=0xf7fe7000 esi=0xf7fe7a20 edi=0xf7fe6b60 ebp=0x00000000 esp=0xffdecc3c
0x5663e120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x5663e009
0x5663e123	'test_x32_c'!0x1123	ret   	                              	
0x5663e009	'test_x32_c'!0x1009	add   	ebx, 0x2fa7                   	ebx=0x56640fb0 SF=0x0 AF=0x1
0x5663e00f	'test_x32_c'!0x100f	mov   	eax, dword ptr [ebx + 0x44]   	eax=0x00000000
0x5663e015	'test_x32_c'!0x1015	test  	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x5663e017	'test_x32_c'!0x1017	je    	5                             	 ZF=1
0x5663e01b	'test_x32_c'!0x101b	add   	esp, 8                        	esp=0xffdecc48 SF=0x1 ZF=0x0
0x5663e01e	'test_x32_c'!0x101e	pop   	ebx                           	ebx=0xf7f93e34
0x5663e01f	'test_x32_c'!0x101f	ret   	                              	
0xf7d87da4	'libc.so.6'!sub_24da4
0x5663e210	'test_x32_c'!0x1210	endbr32	                              	
0x5663e214	'test_x32_c'!0x1214	jmp   	0xffffff5d                    	
0x5663e170	'test_x32_c'!0x1170	call  	0xaa                          	eax=0xffdeccbc ebx=0xf7f93e34 ecx=0x56640eb4 edx=0xf7fe7000 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0x56640eb0 esp=0xffdecc48
0x5663e219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x5663e175
0x5663e21c	'test_x32_c'!0x121c	ret   	                              	
0x5663e175	'test_x32_c'!0x1175	add   	edx, 0x2e3b                   	edx=0x56640fb0 SF=0x0 PF=0x0
0x5663e17b	'test_x32_c'!0x117b	push  	ebp                           	ebp=0x56640eb0
0x5663e17c	'test_x32_c'!0x117c	mov   	ebp, esp                      	ebp=0xffdecc48
0x5663e17e	'test_x32_c'!0x117e	push  	ebx                           	ebx=0xf7f93e34
0x5663e17f	'test_x32_c'!0x117f	lea   	ecx, [edx + 0x58]             	ecx=0x56641008
0x5663e185	'test_x32_c'!0x1185	lea   	eax, [edx + 0x58]             	eax=0x56641008
0x5663e18b	'test_x32_c'!0x118b	sub   	esp, 4                        	esp=0xffdecc40 SF=0x1 AF=0x0
0x5663e18e	'test_x32_c'!0x118e	sub   	eax, ecx                      	eax=0x00000000 SF=0x0 ZF=0x1 PF=0x1
0x5663e190	'test_x32_c'!0x1190	mov   	ebx, eax                      	ebx=0x00000000
0x5663e192	'test_x32_c'!0x1192	shr   	eax, 0x1f                     	eax=0x00000000
0x5663e195	'test_x32_c'!0x1195	sar   	ebx, 2                        	ebx=0x00000000
0x5663e198	'test_x32_c'!0x1198	add   	eax, ebx                      	eax=0x00000000
0x5663e19a	'test_x32_c'!0x119a	sar   	eax, 1                        	eax=0x00000000
0x5663e19c	'test_x32_c'!0x119c	je    	0x17                          	 ZF=1
0x5663e1b2	'test_x32_c'!0x11b2	mov   	ebx, dword ptr [ebp - 4]      	ebx=0xf7f93e34
0x5663e1b5	'test_x32_c'!0x11b5	leave 	                              	
0x5663e1b6	'test_x32_c'!0x11b6	ret   	                              	
0xf7d87e07	'libc.so.6'!sub_24e07
0x5663e31e	'test_x32_c'!0x131e	lea   	ecx, [esp + 4]                	ecx=0xffdecc00
0x5663e322	'test_x32_c'!0x1322	and   	esp, 0xfffffff0               	esp=0xffdecbf0 SF=0x1 ZF=0x0
0x5663e325	'test_x32_c'!0x1325	push  	dword ptr [ecx - 4]           	mem=0xf7d87cb9
0x5663e328	'test_x32_c'!0x1328	push  	ebp                           	ebp=0x00000000
0x5663e329	'test_x32_c'!0x1329	mov   	ebp, esp                      	ebp=0xffdecbe8
0x5663e32b	'test_x32_c'!0x132b	push  	ebx                           	ebx=0xf7f93e34
0x5663e32c	'test_x32_c'!0x132c	push  	ecx                           	ecx=0xffdecc00
0x5663e32d	'test_x32_c'!0x132d	sub   	esp, 0x110                    	esp=0xffdecad0 PF=0x0
0x5663e333	'test_x32_c'!0x1333	call  	0xfffffdee                    	eax=0x5663e31e ebx=0xf7f93e34 ecx=0xffdecc00 edx=0xffdecc20 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecbe8 esp=0xffdecacc
0x5663e120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x5663e338
0x5663e123	'test_x32_c'!0x1123	ret   	                              	
0x5663e338	'test_x32_c'!0x1338	add   	ebx, 0x2c78                   	ebx=0x56640fb0 SF=0x0 AF=0x1
0x5663e33e	'test_x32_c'!0x133e	mov   	eax, dword ptr gs:[0x14]      	eax=0xf7c27c00
0x5663e344	'test_x32_c'!0x1344	mov   	dword ptr [ebp - 0xc], eax    	mem=0xf7c27c00
0x5663e347	'test_x32_c'!0x1347	xor   	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x5663e349	'test_x32_c'!0x1349	sub   	esp, 0xc                      	esp=0xffdecac4 SF=0x1 ZF=0x0 PF=0x0 AF=0x1
0x5663e34c	'test_x32_c'!0x134c	lea   	eax, [ebx - 0x1f64]           	eax=0x5663f04c
0x5663e352	'test_x32_c'!0x1352	push  	eax                           	eax=0x5663f04c
0x5663e353	'test_x32_c'!0x1353	call  	0xfffffd3e                    	eax=0x5663f04c ebx=0x56640fb0 ecx=0xffdecc00 edx=0xffdecc20 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecbe8 esp=0xffdecabc
0x5663e090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0xf7ddb140
0xf7ddb140	'libc.so.6'!_IO_puts
0x5663e358	'test_x32_c'!0x1358	add   	esp, 0x10                     	esp=0xffdecad0 SF=0x1 ZF=0x0 PF=0x0
0x5663e35b	'test_x32_c'!0x135b	sub   	esp, 8                        	esp=0xffdecac8 AF=0x1
0x5663e35e	'test_x32_c'!0x135e	lea   	eax, [ebp - 0x10c]            	eax=0xffdecadc
0x5663e364	'test_x32_c'!0x1364	push  	eax                           	eax=0xffdecadc
0x5663e365	'test_x32_c'!0x1365	lea   	eax, [ebx - 0x1f44]           	eax=0x5663f06c
0x5663e36b	'test_x32_c'!0x136b	push  	eax                           	eax=0x5663f06c
0x5663e36c	'test_x32_c'!0x136c	call  	0xfffffd55                    	eax=0x5663f06c ebx=0x56640fb0 ecx=0xf7f958a0 edx=0x00000000 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecbe8 esp=0xffdecabc
0x5663e0c0	'test_x32_c'!0x10c0	jmp   	dword ptr [ebx + 0x30]        	mem=0xf7dbabd0
0xf7dbabd0	'libc.so.6'!__isoc99_scanf
0x5663e371	'test_x32_c'!0x1371	add   	esp, 0x10                     	esp=0xffdecad0
0x5663e374	'test_x32_c'!0x1374	cmp   	eax, 1                        	eax=0x00000001 SF=0x0 ZF=0x1 PF=0x1
0x5663e377	'test_x32_c'!0x1377	je    	0x26                          	 ZF=1
0x5663e39c	'test_x32_c'!0x139c	call  	0xfffffecf                    	eax=0x00000001 ebx=0x56640fb0 ecx=0x00000000 edx=0xf7fac500 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecbe8 esp=0xffdecacc
0x5663e26a	'test_x32_c'!0x126a	push  	ebp                           	ebp=0xffdecbe8
0x5663e26b	'test_x32_c'!0x126b	mov   	ebp, esp                      	ebp=0xffdecac8
0x5663e26d	'test_x32_c'!0x126d	push  	ebx                           	ebx=0x56640fb0
0x5663e26e	'test_x32_c'!0x126e	sub   	esp, 0x414                    	esp=0xffdec6b0 SF=0x1 ZF=0x0 PF=0x0
0x5663e274	'test_x32_c'!0x1274	call  	0xfffffead                    	eax=0x00000001 ebx=0x56640fb0 ecx=0x00000000 edx=0xf7fac500 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdec6ac
0x5663e120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x5663e279
0x5663e123	'test_x32_c'!0x1123	ret   	                              	
0x5663e279	'test_x32_c'!0x1279	add   	ebx, 0x2d37                   	ebx=0x56640fb0 SF=0x0 AF=0x1
0x5663e27f	'test_x32_c'!0x127f	mov   	eax, dword ptr gs:[0x14]      	eax=0xf7c27c00
0x5663e285	'test_x32_c'!0x1285	mov   	dword ptr [ebp - 0xc], eax    	mem=0xf7c27c00
0x5663e288	'test_x32_c'!0x1288	xor   	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x5663e28a	'test_x32_c'!0x128a	sub   	esp, 8                        	esp=0xffdec6a8 SF=0x1 ZF=0x0 PF=0x0 AF=0x1
0x5663e28d	'test_x32_c'!0x128d	lea   	eax, [ebx - 0x1f95]           	eax=0x5663f01b
0x5663e293	'test_x32_c'!0x1293	push  	eax                           	eax=0x5663f01b
0x5663e294	'test_x32_c'!0x1294	lea   	eax, [ebx - 0x1f93]           	eax=0x5663f01d
0x5663e29a	'test_x32_c'!0x129a	push  	eax                           	eax=0x5663f01d
0x5663e29b	'test_x32_c'!0x129b	call  	0xfffffe16                    	eax=0x5663f01d ebx=0x56640fb0 ecx=0x00000000 edx=0xf7fac500 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdec69c
0x5663e0b0	'test_x32_c'!0x10b0	jmp   	dword ptr [ebx + 0x2c]        	mem=0xf7dd9410
0xf7dd9410	'libc.so.6'!_IO_fopen
0x5663e2a0	'test_x32_c'!0x12a0	add   	esp, 0x10                     	esp=0xffdec6b0 PF=0x0
0x5663e2a3	'test_x32_c'!0x12a3	mov   	dword ptr [ebp - 0x410], eax  	mem=0x585095c0
0x5663e2a9	'test_x32_c'!0x12a9	cmp   	dword ptr [ebp - 0x410], 0    	mem=0x585095c0 SF=0x0 PF=0x1
0x5663e2b0	'test_x32_c'!0x12b0	jne   	0x26                          	 ZF=0
0x5663e2d5	'test_x32_c'!0x12d5	sub   	esp, 4                        	esp=0xffdec6ac SF=0x1 AF=0x1
0x5663e2d8	'test_x32_c'!0x12d8	push  	dword ptr [ebp - 0x410]       	mem=0x585095c0
0x5663e2de	'test_x32_c'!0x12de	push  	0x400                         	
0x5663e2e3	'test_x32_c'!0x12e3	lea   	eax, [ebp - 0x40c]            	eax=0xffdec6bc
0x5663e2e9	'test_x32_c'!0x12e9	push  	eax                           	eax=0xffdec6bc
0x5663e2ea	'test_x32_c'!0x12ea	call  	0xfffffd67                    	eax=0xffdec6bc ebx=0x56640fb0 ecx=0x72702f00 edx=0x2c2c2c2c esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdec69c
0x5663e050	'test_x32_c'!0x1050	jmp   	dword ptr [ebx + 0x14]        	mem=0xf7dd9100
0xf7dd9100	'libc.so.6'!_IO_fgets
0x5663e2ef	'test_x32_c'!0x12ef	add   	esp, 0x10                     	esp=0xffdec6b0 SF=0x1 ZF=0x0 PF=0x0
0x5663e2f2	'test_x32_c'!0x12f2	sub   	esp, 0xc                      	esp=0xffdec6a4 AF=0x1
0x5663e2f5	'test_x32_c'!0x12f5	push  	dword ptr [ebp - 0x410]       	mem=0x585095c0
0x5663e2fb	'test_x32_c'!0x12fb	call  	0xfffffd66                    	eax=0xffdec6bc ebx=0x56640fb0 ecx=0x00000000 edx=0x58509658 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdec69c
0x5663e060	'test_x32_c'!0x1060	jmp   	dword ptr [ebx + 0x18]        	mem=0xf7dd87a0
0xf7dd87a0	'libc.so.6'!fclose
0x5663e300	'test_x32_c'!0x1300	add   	esp, 0x10                     	esp=0xffdec6b0
0x5663e303	'test_x32_c'!0x1303	mov   	eax, 0                        	eax=0x00000000
0x5663e308	'test_x32_c'!0x1308	mov   	edx, dword ptr [ebp - 0xc]    	edx=0xf7c27c00
0x5663e30b	'test_x32_c'!0x130b	sub   	edx, dword ptr gs:[0x14]      	edx=0x00000000 SF=0x0 ZF=0x1 PF=0x1
0x5663e312	'test_x32_c'!0x1312	je    	8                             	 ZF=1
0x5663e319	'test_x32_c'!0x1319	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x56640fb0
0x5663e31c	'test_x32_c'!0x131c	leave 	                              	
0x5663e31d	'test_x32_c'!0x131d	ret   	                              	
0x5663e3a1	'test_x32_c'!0x13a1	call  	0xfffffe7d                    	eax=0x00000000 ebx=0x56640fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecbe8 esp=0xffdecacc
0x5663e21d	'test_x32_c'!0x121d	push  	ebp                           	ebp=0xffdecbe8
0x5663e21e	'test_x32_c'!0x121e	mov   	ebp, esp                      	ebp=0xffdecac8
0x5663e220	'test_x32_c'!0x1220	push  	ebx                           	ebx=0x56640fb0
0x5663e221	'test_x32_c'!0x1221	sub   	esp, 4                        	esp=0xffdecac0 SF=0x1 ZF=0x0
0x5663e224	'test_x32_c'!0x1224	call  	0xfffffefd                    	eax=0x00000000 ebx=0x56640fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdecabc
0x5663e120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x5663e229
0x5663e123	'test_x32_c'!0x1123	ret   	                              	
0x5663e229	'test_x32_c'!0x1229	add   	ebx, 0x2d87                   	ebx=0x56640fb0 SF=0x0 PF=0x0 AF=0x1
0x5663e22f	'test_x32_c'!0x122f	push  	0                             	
0x5663e231	'test_x32_c'!0x1231	push  	0                             	
0x5663e233	'test_x32_c'!0x1233	push  	0                             	
0x5663e235	'test_x32_c'!0x1235	push  	0                             	
0x5663e237	'test_x32_c'!0x1237	call  	0xfffffe9a                    	eax=0x00000000 ebx=0x56640fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdecaac
0x5663e0d0	'test_x32_c'!0x10d0	jmp   	dword ptr [ebx + 0x34]        	mem=0xf7e830e0
0xf7e830e0	'libc.so.6'!ptrace
0x5663e23c	'test_x32_c'!0x123c	add   	esp, 0x10                     	esp=0xffdecac0
0x5663e23f	'test_x32_c'!0x123f	cmp   	eax, -1                       	eax=0xffffffff SF=0x0 ZF=0x1
0x5663e242	'test_x32_c'!0x1242	jne   	0x1f                          	 ZF=1
0x5663e244	'test_x32_c'!0x1244	sub   	esp, 0xc                      	esp=0xffdecab4 SF=0x1 ZF=0x0 AF=0x1
0x5663e247	'test_x32_c'!0x1247	lea   	eax, [ebx - 0x1fa8]           	eax=0x5663f008
0x5663e24d	'test_x32_c'!0x124d	push  	eax                           	eax=0x5663f008
0x5663e24e	'test_x32_c'!0x124e	call  	0xfffffe43                    	eax=0x5663f008 ebx=0x56640fb0 ecx=0xf7fac500 edx=0x00000000 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdecaac
0x5663e090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0xf7ddb140
0xf7ddb140	'libc.so.6'!_IO_puts
0x5663e253	'test_x32_c'!0x1253	add   	esp, 0x10                     	esp=0xffdecac0 SF=0x1 ZF=0x0
0x5663e256	'test_x32_c'!0x1256	sub   	esp, 0xc                      	esp=0xffdecab4 AF=0x1
0x5663e259	'test_x32_c'!0x1259	push  	1                             	
0x5663e25b	'test_x32_c'!0x125b	call  	0xfffffe46                    	eax=0x00000013 ebx=0x56640fb0 ecx=0xf7f958a0 edx=0x00000000 esi=0xffdeccbc edi=0xf7fe6b60 ebp=0xffdecac8 esp=0xffdecaac
0x5663e0a0	'test_x32_c'!0x10a0	jmp   	dword ptr [ebx + 0x28]        	mem=0xf7da1bd0
0xf7da1bd0	'libc.so.6'!exit  
0x5663e1c0	'test_x32_c'!0x11c0	endbr32	                              	
0x5663e1c4	'test_x32_c'!0x11c4	push  	ebp                           	ebp=0xffdeca48
0x5663e1c5	'test_x32_c'!0x11c5	mov   	ebp, esp                      	ebp=0xffdec9c8
0x5663e1c7	'test_x32_c'!0x11c7	push  	ebx                           	ebx=0x56640eb4
0x5663e1c8	'test_x32_c'!0x11c8	call  	0xffffff59                    	eax=0x00000001 ebx=0x56640eb4 ecx=0xffdec9f0 edx=0x00000000 esi=0x56640eb4 edi=0xf7fe7a20 ebp=0xffdec9c8 esp=0xffdec9c0
0x5663e120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x5663e1cd
0x5663e123	'test_x32_c'!0x1123	ret   	                              	
0x5663e1cd	'test_x32_c'!0x11cd	add   	ebx, 0x2de3                   	ebx=0x56640fb0 AF=0x1
0x5663e1d3	'test_x32_c'!0x11d3	sub   	esp, 4                        	esp=0xffdec9c0 SF=0x1 PF=0x1 AF=0x0
0x5663e1d6	'test_x32_c'!0x11d6	cmp   	byte ptr [ebx + 0x58], 0      	mem=0x00000000 SF=0x0 ZF=0x1
0x5663e1dd	'test_x32_c'!0x11dd	jne   	0x2a                          	 ZF=1
0x5663e1df	'test_x32_c'!0x11df	mov   	eax, dword ptr [ebx + 0x40]   	eax=0xf7da1340
0x5663e1e5	'test_x32_c'!0x11e5	test  	eax, eax                      	eax=0xf7da1340 SF=0x1 ZF=0x0 PF=0x0
0x5663e1e7	'test_x32_c'!0x11e7	je    	0x14                          	 ZF=0
0x5663e1e9	'test_x32_c'!0x11e9	sub   	esp, 0xc                      	esp=0xffdec9b4 PF=0x1 AF=0x1
0x5663e1ec	'test_x32_c'!0x11ec	push  	dword ptr [ebx + 0x54]        	mem=0x56641004
0x5663e1f2	'test_x32_c'!0x11f2	call  	0xfffffeef                    	eax=0xf7da1340 ebx=0x56640fb0 ecx=0xffdec9f0 edx=0x00000000 esi=0x56640eb4 edi=0xf7fe7a20 ebp=0xffdec9c8 esp=0xffdec9ac
0x5663e0e0	'test_x32_c'!0x10e0	jmp   	dword ptr [ebx + 0x40]        	mem=0xf7da1340
0xf7da1340	'libc.so.6'!__cxa_finalize
0x5663e1f7	'test_x32_c'!0x11f7	add   	esp, 0x10                     	esp=0xffdec9c0
0x5663e1fa	'test_x32_c'!0x11fa	call  	0xffffff37                    	eax=0x00000001 ebx=0x56640fb0 ecx=0xf7f953c8 edx=0x00000001 esi=0x56640eb4 edi=0xf7fe7a20 ebp=0xffdec9c8 esp=0xffdec9bc
0x5663e130	'test_x32_c'!0x1130	call  	0xea                          	eax=0x00000001 ebx=0x56640fb0 ecx=0xf7f953c8 edx=0x00000001 esi=0x56640eb4 edi=0xf7fe7a20 ebp=0xffdec9c8 esp=0xffdec9b8
0x5663e219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x5663e135
0x5663e21c	'test_x32_c'!0x121c	ret   	                              	
0x5663e135	'test_x32_c'!0x1135	add   	edx, 0x2e7b                   	edx=0x56640fb0 SF=0x0 PF=0x0 AF=0x1
0x5663e13b	'test_x32_c'!0x113b	lea   	ecx, [edx + 0x58]             	ecx=0x56641008
0x5663e141	'test_x32_c'!0x1141	lea   	eax, [edx + 0x58]             	eax=0x56641008
0x5663e147	'test_x32_c'!0x1147	cmp   	eax, ecx                      	eax=0x56641008 ZF=0x1 PF=0x1 AF=0x0
0x5663e149	'test_x32_c'!0x1149	je    	0x20                          	 ZF=1
0x5663e168	'test_x32_c'!0x1168	ret   	                              	
0x5663e1ff	'test_x32_c'!0x11ff	mov   	byte ptr [ebx + 0x58], 1      	mem=0x00000001
0x5663e206	'test_x32_c'!0x1206	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x56640eb4
0x5663e209	'test_x32_c'!0x1209	leave 	                              	
0x5663e20a	'test_x32_c'!0x120a	ret   	                              	
0xf7fb40e2	'ld-linux.so.2'!sub_10e2
0x5663e3f4	'test_x32_c'!0x13f4	push  	ebx                           	ebx=0x00000004
0x5663e3f5	'test_x32_c'!0x13f5	sub   	esp, 8                        	esp=0xffdec9d0 SF=0x1
0x5663e3f8	'test_x32_c'!0x13f8	call  	0xfffffd29                    	eax=0x5663e3f4 ebx=0x00000004 ecx=0x56641008 edx=0x56640ec8 esi=0xf7fe7a20 edi=0x00000001 ebp=0xffdeca48 esp=0xffdec9cc
0x5663e120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x5663e3fd
0x5663e123	'test_x32_c'!0x1123	ret   	                              	
0x5663e3fd	'test_x32_c'!0x13fd	add   	ebx, 0x2bb3                   	ebx=0x56640fb0 SF=0x0 AF=0x1
0x5663e403	'test_x32_c'!0x1403	add   	esp, 8                        	esp=0xffdec9d8 SF=0x1 PF=0x1 AF=0x0
0x5663e406	'test_x32_c'!0x1406	pop   	ebx                           	ebx=0x00000004
0x5663e407	'test_x32_c'!0x1407	ret   	                              	
0xf7fb8079	'ld-linux.so.2'!sub_5079
0xf7da19e6	'libc.so.6'!sub_3e9e6
