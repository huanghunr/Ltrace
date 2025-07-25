eax      0xf7fc6a20    ebx      0xf7fc5fe8    ecx      0xf7fc6d28
edx      0xf7f96e80    esi      0xff918afc    edi      0x565af0f0
ebp      0x00000000    esp      0xff918af0    eip      0x565af0f0
eflags   0x00010282    cs       0x00000023    ss       0x0000002b
ds       0x0000002b    es       0x0000002b    fs       0x00000000
gs       0x00000063
ZF=0x0 SF=0x1 CF=0x0 OF=0x0 PF=0x0 AF=0x0
mm0=0x0    st0=0.0    mm1=0x0    st1=0.0    mm2=0x0    st2=0.0    mm3=0x0    st3=0.0    mm4=0x0    st4=0.0    mm5=0x0    st5=0.0    mm6=0x0    st6=0.0    mm7=0x0    st7=0.0    xmm0=0x0    ymm0=0x0    xmm1=0x0    ymm1=0x0    xmm2=0x0    ymm2=0x0    xmm3=0x0    ymm3=0x0    xmm4=0x0    ymm4=0x0    xmm5=0x0    ymm5=0x0    xmm6=0x0    ymm6=0x0    xmm7=0x0    ymm7=0x0    
-----------
0x565af0f0	'test_x32_c'!0x10f0	xor   	ebp, ebp                      	ebp=0x00000000 SF=0x0 ZF=0x1 PF=0x1
0x565af0f2	'test_x32_c'!0x10f2	pop   	esi                           	esi=0x00000001
0x565af0f3	'test_x32_c'!0x10f3	mov   	ecx, esp                      	ecx=0xff918af4
0x565af0f5	'test_x32_c'!0x10f5	and   	esp, 0xfffffff0               	esp=0xff918af0 SF=0x1 ZF=0x0
0x565af0f8	'test_x32_c'!0x10f8	push  	eax                           	eax=0xf7fc6a20
0x565af0f9	'test_x32_c'!0x10f9	push  	esp                           	esp=0xff918ae8
0x565af0fa	'test_x32_c'!0x10fa	push  	edx                           	edx=0xf7f96e80
0x565af0fb	'test_x32_c'!0x10fb	call  	0x1e                          	eax=0xf7fc6a20 ebx=0xf7fc5fe8 ecx=0xff918af4 edx=0xf7f96e80 esi=0x00000001 edi=0x565af0f0 ebp=0x00000000 esp=0xff918ae0
0x565af118	'test_x32_c'!0x1118	mov   	ebx, dword ptr [esp]          	ebx=0x565af100
0x565af11b	'test_x32_c'!0x111b	ret   	                              	
0x565af100	'test_x32_c'!0x1100	add   	ebx, 0x2eb0                   	ebx=0x565b1fb0 SF=0x0 PF=0x0
0x565af106	'test_x32_c'!0x1106	push  	0                             	
0x565af108	'test_x32_c'!0x1108	push  	0                             	
0x565af10a	'test_x32_c'!0x110a	push  	ecx                           	ecx=0xff918af4
0x565af10b	'test_x32_c'!0x110b	push  	esi                           	esi=0x00000001
0x565af10c	'test_x32_c'!0x110c	push  	dword ptr [ebx + 0x48]        	mem=0x565af31e
0x565af112	'test_x32_c'!0x1112	call  	0xffffff1f                    	eax=0xf7fc6a20 ebx=0x565b1fb0 ecx=0xff918af4 edx=0xf7f96e80 esi=0x00000001 edi=0x565af0f0 ebp=0x00000000 esp=0xff918acc
0x565af030	'test_x32_c'!0x1030	jmp   	dword ptr [ebx + 0xc]         	mem=0xf7d66cf0
0xf7d66cf0	'libc.so.6'!0x24cf0	__libc_start_main
0x565af000	'test_x32_c'!0x1000	push  	ebx                           	ebx=0xf7f72e34
0x565af001	'test_x32_c'!0x1001	sub   	esp, 8                        	esp=0xff918a80 SF=0x1 PF=0x0
0x565af004	'test_x32_c'!0x1004	call  	0x11d                         	eax=0xff918afc ebx=0xf7f72e34 ecx=0x565af000 edx=0xf7fc6000 esi=0xf7fc6a20 edi=0xf7fc5b60 ebp=0x00000000 esp=0xff918a7c
0x565af120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565af009
0x565af123	'test_x32_c'!0x1123	ret   	                              	
0x565af009	'test_x32_c'!0x1009	add   	ebx, 0x2fa7                   	ebx=0x565b1fb0 SF=0x0 AF=0x1
0x565af00f	'test_x32_c'!0x100f	mov   	eax, dword ptr [ebx + 0x44]   	eax=0x00000000
0x565af015	'test_x32_c'!0x1015	test  	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x565af017	'test_x32_c'!0x1017	je    	5                             	
0x565af01b	'test_x32_c'!0x101b	add   	esp, 8                        	esp=0xff918a88 SF=0x1 ZF=0x0
0x565af01e	'test_x32_c'!0x101e	pop   	ebx                           	ebx=0xf7f72e34
0x565af01f	'test_x32_c'!0x101f	ret   	                              	
0xf7d66da4	'libc.so.6'!0x24da4	unknown_lib_function(libc.so.6)
0x565af210	'test_x32_c'!0x1210	endbr32	                              	
0x565af214	'test_x32_c'!0x1214	jmp   	0xffffff5d                    	
0x565af170	'test_x32_c'!0x1170	call  	0xaa                          	eax=0xff918afc ebx=0xf7f72e34 ecx=0x565b1eb4 edx=0xf7fc6000 esi=0xff918afc edi=0xf7fc5b60 ebp=0x565b1eb0 esp=0xff918a88
0x565af219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x565af175
0x565af21c	'test_x32_c'!0x121c	ret   	                              	
0x565af175	'test_x32_c'!0x1175	add   	edx, 0x2e3b                   	edx=0x565b1fb0 SF=0x0 PF=0x0
0x565af17b	'test_x32_c'!0x117b	push  	ebp                           	ebp=0x565b1eb0
0x565af17c	'test_x32_c'!0x117c	mov   	ebp, esp                      	ebp=0xff918a88
0x565af17e	'test_x32_c'!0x117e	push  	ebx                           	ebx=0xf7f72e34
0x565af17f	'test_x32_c'!0x117f	lea   	ecx, [edx + 0x58]             	ecx=0x565b2008
0x565af185	'test_x32_c'!0x1185	lea   	eax, [edx + 0x58]             	eax=0x565b2008
0x565af18b	'test_x32_c'!0x118b	sub   	esp, 4                        	esp=0xff918a80 SF=0x1 AF=0x0
0x565af18e	'test_x32_c'!0x118e	sub   	eax, ecx                      	eax=0x00000000 SF=0x0 ZF=0x1 PF=0x1
0x565af190	'test_x32_c'!0x1190	mov   	ebx, eax                      	ebx=0x00000000
0x565af192	'test_x32_c'!0x1192	shr   	eax, 0x1f                     	eax=0x00000000
0x565af195	'test_x32_c'!0x1195	sar   	ebx, 2                        	ebx=0x00000000
0x565af198	'test_x32_c'!0x1198	add   	eax, ebx                      	eax=0x00000000
0x565af19a	'test_x32_c'!0x119a	sar   	eax, 1                        	eax=0x00000000
0x565af19c	'test_x32_c'!0x119c	je    	0x17                          	
0x565af1b2	'test_x32_c'!0x11b2	mov   	ebx, dword ptr [ebp - 4]      	ebx=0xf7f72e34
0x565af1b5	'test_x32_c'!0x11b5	leave 	                              	
0x565af1b6	'test_x32_c'!0x11b6	ret   	                              	
0xf7d66e07	'libc.so.6'!0x24e07	unknown_lib_function(libc.so.6)
0x565af31e	'test_x32_c'!0x131e	lea   	ecx, [esp + 4]                	ecx=0xff918a40
0x565af322	'test_x32_c'!0x1322	and   	esp, 0xfffffff0               	esp=0xff918a30 SF=0x1 ZF=0x0
0x565af325	'test_x32_c'!0x1325	push  	dword ptr [ecx - 4]           	mem=0xf7d66cb9
0x565af328	'test_x32_c'!0x1328	push  	ebp                           	ebp=0x00000000
0x565af329	'test_x32_c'!0x1329	mov   	ebp, esp                      	ebp=0xff918a28
0x565af32b	'test_x32_c'!0x132b	push  	ebx                           	ebx=0xf7f72e34
0x565af32c	'test_x32_c'!0x132c	push  	ecx                           	ecx=0xff918a40
0x565af32d	'test_x32_c'!0x132d	sub   	esp, 0x110                    	esp=0xff918910 PF=0x0
0x565af333	'test_x32_c'!0x1333	call  	0xfffffdee                    	eax=0x565af31e ebx=0xf7f72e34 ecx=0xff918a40 edx=0xff918a60 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918a28 esp=0xff91890c
0x565af120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565af338
0x565af123	'test_x32_c'!0x1123	ret   	                              	
0x565af338	'test_x32_c'!0x1338	add   	ebx, 0x2c78                   	ebx=0x565b1fb0 SF=0x0 AF=0x1
0x565af33e	'test_x32_c'!0x133e	mov   	eax, dword ptr gs:[0x14]      	eax=0x76ac5100
0x565af344	'test_x32_c'!0x1344	mov   	dword ptr [ebp - 0xc], eax    	mem=0x76ac5100
0x565af347	'test_x32_c'!0x1347	xor   	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x565af349	'test_x32_c'!0x1349	sub   	esp, 0xc                      	esp=0xff918904 SF=0x1 ZF=0x0 PF=0x0 AF=0x1
0x565af34c	'test_x32_c'!0x134c	lea   	eax, [ebx - 0x1f64]           	eax=0x565b004c
0x565af352	'test_x32_c'!0x1352	push  	eax                           	eax=0x565b004c
0x565af353	'test_x32_c'!0x1353	call  	0xfffffd3e                    	eax=0x565b004c ebx=0x565b1fb0 ecx=0xff918a40 edx=0xff918a60 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918a28 esp=0xff9188fc
0x565af090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0xf7dba140
0xf7dba140	'libc.so.6'!0x78140	_IO_puts
0x565af358	'test_x32_c'!0x1358	add   	esp, 0x10                     	esp=0xff918910 SF=0x1 ZF=0x0 PF=0x0
0x565af35b	'test_x32_c'!0x135b	sub   	esp, 8                        	esp=0xff918908 AF=0x1
0x565af35e	'test_x32_c'!0x135e	lea   	eax, [ebp - 0x10c]            	eax=0xff91891c
0x565af364	'test_x32_c'!0x1364	push  	eax                           	eax=0xff91891c
0x565af365	'test_x32_c'!0x1365	lea   	eax, [ebx - 0x1f44]           	eax=0x565b006c
0x565af36b	'test_x32_c'!0x136b	push  	eax                           	eax=0x565b006c
0x565af36c	'test_x32_c'!0x136c	call  	0xfffffd55                    	eax=0x565b006c ebx=0x565b1fb0 ecx=0xf7f748a0 edx=0x00000000 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918a28 esp=0xff9188fc
0x565af0c0	'test_x32_c'!0x10c0	jmp   	dword ptr [ebx + 0x30]        	mem=0xf7d99bd0
0xf7d99bd0	'libc.so.6'!0x57bd0	__isoc99_scanf
0x565af371	'test_x32_c'!0x1371	add   	esp, 0x10                     	esp=0xff918910 PF=0x0
0x565af374	'test_x32_c'!0x1374	cmp   	eax, 1                        	eax=0x00000001 SF=0x0 ZF=0x1 PF=0x1
0x565af377	'test_x32_c'!0x1377	je    	0x26                          	
0x565af39c	'test_x32_c'!0x139c	call  	0xfffffecf                    	eax=0x00000001 ebx=0x565b1fb0 ecx=0x00000000 edx=0xf7f8b500 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918a28 esp=0xff91890c
0x565af26a	'test_x32_c'!0x126a	push  	ebp                           	ebp=0xff918a28
0x565af26b	'test_x32_c'!0x126b	mov   	ebp, esp                      	ebp=0xff918908
0x565af26d	'test_x32_c'!0x126d	push  	ebx                           	ebx=0x565b1fb0
0x565af26e	'test_x32_c'!0x126e	sub   	esp, 0x414                    	esp=0xff9184f0 SF=0x1 ZF=0x0
0x565af274	'test_x32_c'!0x1274	call  	0xfffffead                    	eax=0x00000001 ebx=0x565b1fb0 ecx=0x00000000 edx=0xf7f8b500 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9184ec
0x565af120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565af279
0x565af123	'test_x32_c'!0x1123	ret   	                              	
0x565af279	'test_x32_c'!0x1279	add   	ebx, 0x2d37                   	ebx=0x565b1fb0 SF=0x0 PF=0x0 AF=0x1
0x565af27f	'test_x32_c'!0x127f	mov   	eax, dword ptr gs:[0x14]      	eax=0x76ac5100
0x565af285	'test_x32_c'!0x1285	mov   	dword ptr [ebp - 0xc], eax    	mem=0x76ac5100
0x565af288	'test_x32_c'!0x1288	xor   	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x565af28a	'test_x32_c'!0x128a	sub   	esp, 8                        	esp=0xff9184e8 SF=0x1 ZF=0x0 AF=0x1
0x565af28d	'test_x32_c'!0x128d	lea   	eax, [ebx - 0x1f95]           	eax=0x565b001b
0x565af293	'test_x32_c'!0x1293	push  	eax                           	eax=0x565b001b
0x565af294	'test_x32_c'!0x1294	lea   	eax, [ebx - 0x1f93]           	eax=0x565b001d
0x565af29a	'test_x32_c'!0x129a	push  	eax                           	eax=0x565b001d
0x565af29b	'test_x32_c'!0x129b	call  	0xfffffe16                    	eax=0x565b001d ebx=0x565b1fb0 ecx=0x00000000 edx=0xf7f8b500 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9184dc
0x565af0b0	'test_x32_c'!0x10b0	jmp   	dword ptr [ebx + 0x2c]        	mem=0xf7db8410
0xf7db8410	'libc.so.6'!0x76410	_IO_fopen
0x565af2a0	'test_x32_c'!0x12a0	add   	esp, 0x10                     	esp=0xff9184f0 PF=0x1
0x565af2a3	'test_x32_c'!0x12a3	mov   	dword ptr [ebp - 0x410], eax  	mem=0x56e9d5c0
0x565af2a9	'test_x32_c'!0x12a9	cmp   	dword ptr [ebp - 0x410], 0    	mem=0x56e9d5c0 SF=0x0
0x565af2b0	'test_x32_c'!0x12b0	jne   	0x26                          	
0x565af2d5	'test_x32_c'!0x12d5	sub   	esp, 4                        	esp=0xff9184ec SF=0x1 PF=0x0 AF=0x1
0x565af2d8	'test_x32_c'!0x12d8	push  	dword ptr [ebp - 0x410]       	mem=0x56e9d5c0
0x565af2de	'test_x32_c'!0x12de	push  	0x400                         	
0x565af2e3	'test_x32_c'!0x12e3	lea   	eax, [ebp - 0x40c]            	eax=0xff9184fc
0x565af2e9	'test_x32_c'!0x12e9	push  	eax                           	eax=0xff9184fc
0x565af2ea	'test_x32_c'!0x12ea	call  	0xfffffd67                    	eax=0xff9184fc ebx=0x565b1fb0 ecx=0x72702f00 edx=0x2c2c2c2c esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9184dc
0x565af050	'test_x32_c'!0x1050	jmp   	dword ptr [ebx + 0x14]        	mem=0xf7db8100
0xf7db8100	'libc.so.6'!0x76100	_IO_fgets
0x565af2ef	'test_x32_c'!0x12ef	add   	esp, 0x10                     	esp=0xff9184f0 SF=0x1 ZF=0x0
0x565af2f2	'test_x32_c'!0x12f2	sub   	esp, 0xc                      	esp=0xff9184e4 AF=0x1
0x565af2f5	'test_x32_c'!0x12f5	push  	dword ptr [ebp - 0x410]       	mem=0x56e9d5c0
0x565af2fb	'test_x32_c'!0x12fb	call  	0xfffffd66                    	eax=0xff9184fc ebx=0x565b1fb0 ecx=0x00000000 edx=0x56e9d658 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9184dc
0x565af060	'test_x32_c'!0x1060	jmp   	dword ptr [ebx + 0x18]        	mem=0xf7db77a0
0xf7db77a0	'libc.so.6'!0x757a0	fclose
0x565af300	'test_x32_c'!0x1300	add   	esp, 0x10                     	esp=0xff9184f0 PF=0x1
0x565af303	'test_x32_c'!0x1303	mov   	eax, 0                        	eax=0x00000000
0x565af308	'test_x32_c'!0x1308	mov   	edx, dword ptr [ebp - 0xc]    	edx=0x76ac5100
0x565af30b	'test_x32_c'!0x130b	sub   	edx, dword ptr gs:[0x14]      	edx=0x00000000 SF=0x0 ZF=0x1
0x565af312	'test_x32_c'!0x1312	je    	8                             	
0x565af319	'test_x32_c'!0x1319	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x565b1fb0
0x565af31c	'test_x32_c'!0x131c	leave 	                              	
0x565af31d	'test_x32_c'!0x131d	ret   	                              	
0x565af3a1	'test_x32_c'!0x13a1	call  	0xfffffe7d                    	eax=0x00000000 ebx=0x565b1fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918a28 esp=0xff91890c
0x565af21d	'test_x32_c'!0x121d	push  	ebp                           	ebp=0xff918a28
0x565af21e	'test_x32_c'!0x121e	mov   	ebp, esp                      	ebp=0xff918908
0x565af220	'test_x32_c'!0x1220	push  	ebx                           	ebx=0x565b1fb0
0x565af221	'test_x32_c'!0x1221	sub   	esp, 4                        	esp=0xff918900 SF=0x1 ZF=0x0
0x565af224	'test_x32_c'!0x1224	call  	0xfffffefd                    	eax=0x00000000 ebx=0x565b1fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9188fc
0x565af120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565af229
0x565af123	'test_x32_c'!0x1123	ret   	                              	
0x565af229	'test_x32_c'!0x1229	add   	ebx, 0x2d87                   	ebx=0x565b1fb0 SF=0x0 PF=0x0 AF=0x1
0x565af22f	'test_x32_c'!0x122f	push  	0                             	
0x565af231	'test_x32_c'!0x1231	push  	0                             	
0x565af233	'test_x32_c'!0x1233	push  	0                             	
0x565af235	'test_x32_c'!0x1235	push  	0                             	
0x565af237	'test_x32_c'!0x1237	call  	0xfffffe9a                    	eax=0x00000000 ebx=0x565b1fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9188ec
0x565af0d0	'test_x32_c'!0x10d0	jmp   	dword ptr [ebx + 0x34]        	mem=0xf7e620e0
0xf7e620e0	'libc.so.6'!0x1200e0	ptrace
0x565af23c	'test_x32_c'!0x123c	add   	esp, 0x10                     	esp=0xff918900 PF=0x1
0x565af23f	'test_x32_c'!0x123f	cmp   	eax, -1                       	eax=0xffffffff SF=0x0 ZF=0x1
0x565af242	'test_x32_c'!0x1242	jne   	0x1f                          	
0x565af244	'test_x32_c'!0x1244	sub   	esp, 0xc                      	esp=0xff9188f4 SF=0x1 ZF=0x0 PF=0x0 AF=0x1
0x565af247	'test_x32_c'!0x1247	lea   	eax, [ebx - 0x1fa8]           	eax=0x565b0008
0x565af24d	'test_x32_c'!0x124d	push  	eax                           	eax=0x565b0008
0x565af24e	'test_x32_c'!0x124e	call  	0xfffffe43                    	eax=0x565b0008 ebx=0x565b1fb0 ecx=0xf7f8b500 edx=0x00000000 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9188ec
0x565af090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0xf7dba140
0xf7dba140	'libc.so.6'!0x78140	_IO_puts
0x565af253	'test_x32_c'!0x1253	add   	esp, 0x10                     	esp=0xff918900 SF=0x1 ZF=0x0
0x565af256	'test_x32_c'!0x1256	sub   	esp, 0xc                      	esp=0xff9188f4 PF=0x0 AF=0x1
0x565af259	'test_x32_c'!0x1259	push  	1                             	
0x565af25b	'test_x32_c'!0x125b	call  	0xfffffe46                    	eax=0x00000013 ebx=0x565b1fb0 ecx=0xf7f748a0 edx=0x00000000 esi=0xff918afc edi=0xf7fc5b60 ebp=0xff918908 esp=0xff9188ec
0x565af0a0	'test_x32_c'!0x10a0	jmp   	dword ptr [ebx + 0x28]        	mem=0xf7d80bd0
0xf7d80bd0	'libc.so.6'!0x3ebd0	exit  
0x565af1c0	'test_x32_c'!0x11c0	endbr32	                              	
0x565af1c4	'test_x32_c'!0x11c4	push  	ebp                           	ebp=0xff918888
0x565af1c5	'test_x32_c'!0x11c5	mov   	ebp, esp                      	ebp=0xff918808
0x565af1c7	'test_x32_c'!0x11c7	push  	ebx                           	ebx=0x565b1eb4
0x565af1c8	'test_x32_c'!0x11c8	call  	0xffffff59                    	eax=0x00000001 ebx=0x565b1eb4 ecx=0xff918830 edx=0x00000000 esi=0x565b1eb4 edi=0xf7fc6a20 ebp=0xff918808 esp=0xff918800
0x565af120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565af1cd
0x565af123	'test_x32_c'!0x1123	ret   	                              	
0x565af1cd	'test_x32_c'!0x11cd	add   	ebx, 0x2de3                   	ebx=0x565b1fb0 AF=0x1
0x565af1d3	'test_x32_c'!0x11d3	sub   	esp, 4                        	esp=0xff918800 SF=0x1 PF=0x1 AF=0x0
0x565af1d6	'test_x32_c'!0x11d6	cmp   	byte ptr [ebx + 0x58], 0      	mem=0x00000000 SF=0x0 ZF=0x1
0x565af1dd	'test_x32_c'!0x11dd	jne   	0x2a                          	
0x565af1df	'test_x32_c'!0x11df	mov   	eax, dword ptr [ebx + 0x40]   	eax=0xf7d80340
0x565af1e5	'test_x32_c'!0x11e5	test  	eax, eax                      	eax=0xf7d80340 SF=0x1 ZF=0x0 PF=0x0
0x565af1e7	'test_x32_c'!0x11e7	je    	0x14                          	
0x565af1e9	'test_x32_c'!0x11e9	sub   	esp, 0xc                      	esp=0xff9187f4 AF=0x1
0x565af1ec	'test_x32_c'!0x11ec	push  	dword ptr [ebx + 0x54]        	mem=0x565b2004
0x565af1f2	'test_x32_c'!0x11f2	call  	0xfffffeef                    	eax=0xf7d80340 ebx=0x565b1fb0 ecx=0xff918830 edx=0x00000000 esi=0x565b1eb4 edi=0xf7fc6a20 ebp=0xff918808 esp=0xff9187ec
0x565af0e0	'test_x32_c'!0x10e0	jmp   	dword ptr [ebx + 0x40]        	mem=0xf7d80340
0xf7d80340	'libc.so.6'!0x3e340	__cxa_finalize
0x565af1f7	'test_x32_c'!0x11f7	add   	esp, 0x10                     	esp=0xff918800 PF=0x1
0x565af1fa	'test_x32_c'!0x11fa	call  	0xffffff37                    	eax=0x00000001 ebx=0x565b1fb0 ecx=0xf7f743c8 edx=0x00000001 esi=0x565b1eb4 edi=0xf7fc6a20 ebp=0xff918808 esp=0xff9187fc
0x565af130	'test_x32_c'!0x1130	call  	0xea                          	eax=0x00000001 ebx=0x565b1fb0 ecx=0xf7f743c8 edx=0x00000001 esi=0x565b1eb4 edi=0xf7fc6a20 ebp=0xff918808 esp=0xff9187f8
0x565af219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x565af135
0x565af21c	'test_x32_c'!0x121c	ret   	                              	
0x565af135	'test_x32_c'!0x1135	add   	edx, 0x2e7b                   	edx=0x565b1fb0 SF=0x0 PF=0x0 AF=0x1
0x565af13b	'test_x32_c'!0x113b	lea   	ecx, [edx + 0x58]             	ecx=0x565b2008
0x565af141	'test_x32_c'!0x1141	lea   	eax, [edx + 0x58]             	eax=0x565b2008
0x565af147	'test_x32_c'!0x1147	cmp   	eax, ecx                      	eax=0x565b2008 ZF=0x1 PF=0x1 AF=0x0
0x565af149	'test_x32_c'!0x1149	je    	0x20                          	
0x565af168	'test_x32_c'!0x1168	ret   	                              	
0x565af1ff	'test_x32_c'!0x11ff	mov   	byte ptr [ebx + 0x58], 1      	mem=0x00000001
0x565af206	'test_x32_c'!0x1206	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x565b1eb4
0x565af209	'test_x32_c'!0x1209	leave 	                              	
0x565af20a	'test_x32_c'!0x120a	ret   	                              	
0xf7f930e2	'ld-linux.so.2'!0x10e2	unknown_lib_function(ld-linux.so.2)
0x565af3f4	'test_x32_c'!0x13f4	push  	ebx                           	ebx=0x00000004
0x565af3f5	'test_x32_c'!0x13f5	sub   	esp, 8                        	esp=0xff918810 SF=0x1
0x565af3f8	'test_x32_c'!0x13f8	call  	0xfffffd29                    	eax=0x565af3f4 ebx=0x00000004 ecx=0x565b2008 edx=0x565b1ec8 esi=0xf7fc6a20 edi=0x00000001 ebp=0xff918888 esp=0xff91880c
0x565af120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565af3fd
0x565af123	'test_x32_c'!0x1123	ret   	                              	
0x565af3fd	'test_x32_c'!0x13fd	add   	ebx, 0x2bb3                   	ebx=0x565b1fb0 SF=0x0 AF=0x1
0x565af403	'test_x32_c'!0x1403	add   	esp, 8                        	esp=0xff918818 SF=0x1 PF=0x1 AF=0x0
0x565af406	'test_x32_c'!0x1406	pop   	ebx                           	ebx=0x00000004
0x565af407	'test_x32_c'!0x1407	ret   	                              	
0xf7f97079	'ld-linux.so.2'!0x5079	unknown_lib_function(ld-linux.so.2)
