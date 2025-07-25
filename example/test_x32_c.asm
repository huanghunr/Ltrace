eax      0x00000000f7f69a20    ebx      0x00000000f7f68fe8    ecx      0x00000000f7f69d28
edx      0x00000000f7f39e80    esi      0x00000000ffb144dc    edi      0x00000000565900f0
ebp      0x0000000000000000    esp      0x00000000ffb144d0    eip      0x00000000565900f0
eflags   0x0000000000010286    cs       0x0000000000000023    ss       0x000000000000002b
ds       0x000000000000002b    es       0x000000000000002b    fs       0x0000000000000000
gs       0x0000000000000063
ZF=0x0 SF=0x1 CF=0x0 OF=0x0 PF=0x1 AF=0x0
mm0=0x0    st0=0.0    mm1=0x0    st1=0.0    mm2=0x0    st2=0.0    mm3=0x0    st3=0.0    mm4=0x0    st4=0.0    mm5=0x0    st5=0.0    mm6=0x0    st6=0.0    mm7=0x0    st7=0.0    xmm0=0x0    ymm0=0x0    xmm1=0x0    ymm1=0x0    xmm2=0x0    ymm2=0x0    xmm3=0x0    ymm3=0x0    xmm4=0x0    ymm4=0x0    xmm5=0x0    ymm5=0x0    xmm6=0x0    ymm6=0x0    xmm7=0x0    ymm7=0x0    
-----------
0x565900f0	'test_x32_c'!0x10f0	xor   	ebp, ebp                      	ebp=0x0000000000000000 SF=0x0 ZF=0x1
0x565900f2	'test_x32_c'!0x10f2	pop   	esi                           	esi=0x0000000000000001
0x565900f3	'test_x32_c'!0x10f3	mov   	ecx, esp                      	ecx=0x00000000ffb144d4
0x565900f5	'test_x32_c'!0x10f5	and   	esp, 0xfffffff0               	esp=0x00000000ffb144d0 SF=0x1 ZF=0x0 PF=0x0
0x565900f8	'test_x32_c'!0x10f8	push  	eax                           	eax=0x00000000f7f69a20
0x565900f9	'test_x32_c'!0x10f9	push  	esp                           	esp=0x00000000ffb144c8
0x565900fa	'test_x32_c'!0x10fa	push  	edx                           	edx=0x00000000f7f39e80
0x565900fb	'test_x32_c'!0x10fb	call  	0x1e                          	eax=0x00000000f7f69a20 ebx=0x00000000f7f68fe8 ecx=0x00000000ffb144d4 edx=0x00000000f7f39e80 esi=0x0000000000000001 edi=0x00000000565900f0 ebp=0x0000000000000000 esp=0x00000000ffb144c0
0x56590118	'test_x32_c'!0x1118	mov   	ebx, dword ptr [esp]          	ebx=0x0000000056590100
0x5659011b	'test_x32_c'!0x111b	ret   	                              	
0x56590100	'test_x32_c'!0x1100	add   	ebx, 0x2eb0                   	ebx=0x0000000056592fb0 SF=0x0
0x56590106	'test_x32_c'!0x1106	push  	0                             	
0x56590108	'test_x32_c'!0x1108	push  	0                             	
0x5659010a	'test_x32_c'!0x110a	push  	ecx                           	ecx=0x00000000ffb144d4
0x5659010b	'test_x32_c'!0x110b	push  	esi                           	esi=0x0000000000000001
0x5659010c	'test_x32_c'!0x110c	push  	dword ptr [ebx + 0x48]        	mem=0x000000005659031e
0x56590112	'test_x32_c'!0x1112	call  	0xffffff1f                    	eax=0x00000000f7f69a20 ebx=0x0000000056592fb0 ecx=0x00000000ffb144d4 edx=0x00000000f7f39e80 esi=0x0000000000000001 edi=0x00000000565900f0 ebp=0x0000000000000000 esp=0x00000000ffb144ac
0x56590030	'test_x32_c'!0x1030	jmp   	dword ptr [ebx + 0xc]         	mem=0x00000000f7d09cf0
0xf7d09cf0	'libc.so.6'!0x24cf0	__libc_start_main
0x56590000	'test_x32_c'!0x1000	push  	ebx                           	ebx=0x00000000f7f15e34
0x56590001	'test_x32_c'!0x1001	sub   	esp, 8                        	esp=0x00000000ffb14460 SF=0x1
0x56590004	'test_x32_c'!0x1004	call  	0x11d                         	eax=0x00000000ffb144dc ebx=0x00000000f7f15e34 ecx=0x0000000056590000 edx=0x00000000f7f69000 esi=0x00000000f7f69a20 edi=0x00000000f7f68b60 ebp=0x0000000000000000 esp=0x00000000ffb1445c
0x56590120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x0000000056590009
0x56590123	'test_x32_c'!0x1123	ret   	                              	
0x56590009	'test_x32_c'!0x1009	add   	ebx, 0x2fa7                   	ebx=0x0000000056592fb0 SF=0x0 PF=0x0 AF=0x1
0x5659000f	'test_x32_c'!0x100f	mov   	eax, dword ptr [ebx + 0x44]   	eax=0x0000000000000000
0x56590015	'test_x32_c'!0x1015	test  	eax, eax                      	eax=0x0000000000000000 ZF=0x1 PF=0x1 AF=0x0
0x56590017	'test_x32_c'!0x1017	je    	5                             	
0x5659001b	'test_x32_c'!0x101b	add   	esp, 8                        	esp=0x00000000ffb14468 SF=0x1 ZF=0x0 PF=0x0
0x5659001e	'test_x32_c'!0x101e	pop   	ebx                           	ebx=0x00000000f7f15e34
0x5659001f	'test_x32_c'!0x101f	ret   	                              	
0xf7d09da4	'libc.so.6'!0x24da4	unknown_lib_function(libc.so.6)
0x56590210	'test_x32_c'!0x1210	endbr32	                              	
0x56590214	'test_x32_c'!0x1214	jmp   	0xffffff5d                    	
0x56590170	'test_x32_c'!0x1170	call  	0xaa                          	eax=0x00000000ffb144dc ebx=0x00000000f7f15e34 ecx=0x0000000056592eb4 edx=0x00000000f7f69000 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x0000000056592eb0 esp=0x00000000ffb14468
0x56590219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x0000000056590175
0x5659021c	'test_x32_c'!0x121c	ret   	                              	
0x56590175	'test_x32_c'!0x1175	add   	edx, 0x2e3b                   	edx=0x0000000056592fb0 SF=0x0
0x5659017b	'test_x32_c'!0x117b	push  	ebp                           	ebp=0x0000000056592eb0
0x5659017c	'test_x32_c'!0x117c	mov   	ebp, esp                      	ebp=0x00000000ffb14468
0x5659017e	'test_x32_c'!0x117e	push  	ebx                           	ebx=0x00000000f7f15e34
0x5659017f	'test_x32_c'!0x117f	lea   	ecx, [edx + 0x58]             	ecx=0x0000000056593008
0x56590185	'test_x32_c'!0x1185	lea   	eax, [edx + 0x58]             	eax=0x0000000056593008
0x5659018b	'test_x32_c'!0x118b	sub   	esp, 4                        	esp=0x00000000ffb14460 SF=0x1 PF=0x1 AF=0x0
0x5659018e	'test_x32_c'!0x118e	sub   	eax, ecx                      	eax=0x0000000000000000 SF=0x0 ZF=0x1
0x56590190	'test_x32_c'!0x1190	mov   	ebx, eax                      	ebx=0x0000000000000000
0x56590192	'test_x32_c'!0x1192	shr   	eax, 0x1f                     	eax=0x0000000000000000
0x56590195	'test_x32_c'!0x1195	sar   	ebx, 2                        	ebx=0x0000000000000000
0x56590198	'test_x32_c'!0x1198	add   	eax, ebx                      	eax=0x0000000000000000
0x5659019a	'test_x32_c'!0x119a	sar   	eax, 1                        	eax=0x0000000000000000
0x5659019c	'test_x32_c'!0x119c	je    	0x17                          	
0x565901b2	'test_x32_c'!0x11b2	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x00000000f7f15e34
0x565901b5	'test_x32_c'!0x11b5	leave 	                              	
0x565901b6	'test_x32_c'!0x11b6	ret   	                              	
0xf7d09e07	'libc.so.6'!0x24e07	unknown_lib_function(libc.so.6)
0x5659031e	'test_x32_c'!0x131e	lea   	ecx, [esp + 4]                	ecx=0x00000000ffb14420
0x56590322	'test_x32_c'!0x1322	and   	esp, 0xfffffff0               	esp=0x00000000ffb14410 SF=0x1 ZF=0x0 PF=0x0
0x56590325	'test_x32_c'!0x1325	push  	dword ptr [ecx - 4]           	mem=0x00000000f7d09cb9
0x56590328	'test_x32_c'!0x1328	push  	ebp                           	ebp=0x0000000000000000
0x56590329	'test_x32_c'!0x1329	mov   	ebp, esp                      	ebp=0x00000000ffb14408
0x5659032b	'test_x32_c'!0x132b	push  	ebx                           	ebx=0x00000000f7f15e34
0x5659032c	'test_x32_c'!0x132c	push  	ecx                           	ecx=0x00000000ffb14420
0x5659032d	'test_x32_c'!0x132d	sub   	esp, 0x110                    	esp=0x00000000ffb142f0 PF=0x1
0x56590333	'test_x32_c'!0x1333	call  	0xfffffdee                    	eax=0x000000005659031e ebx=0x00000000f7f15e34 ecx=0x00000000ffb14420 edx=0x00000000ffb14440 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb14408 esp=0x00000000ffb142ec
0x56590120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x0000000056590338
0x56590123	'test_x32_c'!0x1123	ret   	                              	
0x56590338	'test_x32_c'!0x1338	add   	ebx, 0x2c78                   	ebx=0x0000000056592fb0 SF=0x0 PF=0x0 AF=0x1
0x5659033e	'test_x32_c'!0x133e	mov   	eax, dword ptr gs:[0x14]      	eax=0x0000000048d6e200
0x56590344	'test_x32_c'!0x1344	mov   	dword ptr [ebp - 0xc], eax    	mem=0x0000000048d6e200
0x56590347	'test_x32_c'!0x1347	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1 PF=0x1 AF=0x0
0x56590349	'test_x32_c'!0x1349	sub   	esp, 0xc                      	esp=0x00000000ffb142e4 SF=0x1 ZF=0x0 AF=0x1
0x5659034c	'test_x32_c'!0x134c	lea   	eax, [ebx - 0x1f64]           	eax=0x000000005659104c
0x56590352	'test_x32_c'!0x1352	push  	eax                           	eax=0x000000005659104c
0x56590353	'test_x32_c'!0x1353	call  	0xfffffd3e                    	eax=0x000000005659104c ebx=0x0000000056592fb0 ecx=0x00000000ffb14420 edx=0x00000000ffb14440 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb14408 esp=0x00000000ffb142dc
0x56590090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0x00000000f7d5d140
0xf7d5d140	'libc.so.6'!0x78140	_IO_puts
0x56590358	'test_x32_c'!0x1358	add   	esp, 0x10                     	esp=0x00000000ffb142f0 SF=0x1 ZF=0x0
0x5659035b	'test_x32_c'!0x135b	sub   	esp, 8                        	esp=0x00000000ffb142e8 AF=0x1
0x5659035e	'test_x32_c'!0x135e	lea   	eax, [ebp - 0x10c]            	eax=0x00000000ffb142fc
0x56590364	'test_x32_c'!0x1364	push  	eax                           	eax=0x00000000ffb142fc
0x56590365	'test_x32_c'!0x1365	lea   	eax, [ebx - 0x1f44]           	eax=0x000000005659106c
0x5659036b	'test_x32_c'!0x136b	push  	eax                           	eax=0x000000005659106c
0x5659036c	'test_x32_c'!0x136c	call  	0xfffffd55                    	eax=0x000000005659106c ebx=0x0000000056592fb0 ecx=0x00000000f7f178a0 edx=0x0000000000000000 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb14408 esp=0x00000000ffb142dc
0x565900c0	'test_x32_c'!0x10c0	jmp   	dword ptr [ebx + 0x30]        	mem=0x00000000f7d3cbd0
0xf7d3cbd0	'libc.so.6'!0x57bd0	__isoc99_scanf
0x56590371	'test_x32_c'!0x1371	add   	esp, 0x10                     	esp=0x00000000ffb142f0 PF=0x1
0x56590374	'test_x32_c'!0x1374	cmp   	eax, 1                        	eax=0x0000000000000001 SF=0x0 ZF=0x1
0x56590377	'test_x32_c'!0x1377	je    	0x26                          	
0x5659039c	'test_x32_c'!0x139c	call  	0xfffffecf                    	eax=0x0000000000000001 ebx=0x0000000056592fb0 ecx=0x0000000000000000 edx=0x00000000f7f2e500 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb14408 esp=0x00000000ffb142ec
0x5659026a	'test_x32_c'!0x126a	push  	ebp                           	ebp=0x00000000ffb14408
0x5659026b	'test_x32_c'!0x126b	mov   	ebp, esp                      	ebp=0x00000000ffb142e8
0x5659026d	'test_x32_c'!0x126d	push  	ebx                           	ebx=0x0000000056592fb0
0x5659026e	'test_x32_c'!0x126e	sub   	esp, 0x414                    	esp=0x00000000ffb13ed0 SF=0x1 ZF=0x0 PF=0x0
0x56590274	'test_x32_c'!0x1274	call  	0xfffffead                    	eax=0x0000000000000001 ebx=0x0000000056592fb0 ecx=0x0000000000000000 edx=0x00000000f7f2e500 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb13ecc
0x56590120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x0000000056590279
0x56590123	'test_x32_c'!0x1123	ret   	                              	
0x56590279	'test_x32_c'!0x1279	add   	ebx, 0x2d37                   	ebx=0x0000000056592fb0 SF=0x0 AF=0x1
0x5659027f	'test_x32_c'!0x127f	mov   	eax, dword ptr gs:[0x14]      	eax=0x0000000048d6e200
0x56590285	'test_x32_c'!0x1285	mov   	dword ptr [ebp - 0xc], eax    	mem=0x0000000048d6e200
0x56590288	'test_x32_c'!0x1288	xor   	eax, eax                      	eax=0x0000000000000000 ZF=0x1 PF=0x1 AF=0x0
0x5659028a	'test_x32_c'!0x128a	sub   	esp, 8                        	esp=0x00000000ffb13ec8 SF=0x1 ZF=0x0 PF=0x0 AF=0x1
0x5659028d	'test_x32_c'!0x128d	lea   	eax, [ebx - 0x1f95]           	eax=0x000000005659101b
0x56590293	'test_x32_c'!0x1293	push  	eax                           	eax=0x000000005659101b
0x56590294	'test_x32_c'!0x1294	lea   	eax, [ebx - 0x1f93]           	eax=0x000000005659101d
0x5659029a	'test_x32_c'!0x129a	push  	eax                           	eax=0x000000005659101d
0x5659029b	'test_x32_c'!0x129b	call  	0xfffffe16                    	eax=0x000000005659101d ebx=0x0000000056592fb0 ecx=0x0000000000000000 edx=0x00000000f7f2e500 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb13ebc
0x565900b0	'test_x32_c'!0x10b0	jmp   	dword ptr [ebx + 0x2c]        	mem=0x00000000f7d5b410
0xf7d5b410	'libc.so.6'!0x76410	_IO_fopen
0x565902a0	'test_x32_c'!0x12a0	add   	esp, 0x10                     	esp=0x00000000ffb13ed0
0x565902a3	'test_x32_c'!0x12a3	mov   	dword ptr [ebp - 0x410], eax  	mem=0x00000000582ef5c0
0x565902a9	'test_x32_c'!0x12a9	cmp   	dword ptr [ebp - 0x410], 0    	mem=0x00000000582ef5c0 SF=0x0 PF=0x1
0x565902b0	'test_x32_c'!0x12b0	jne   	0x26                          	
0x565902d5	'test_x32_c'!0x12d5	sub   	esp, 4                        	esp=0x00000000ffb13ecc SF=0x1 AF=0x1
0x565902d8	'test_x32_c'!0x12d8	push  	dword ptr [ebp - 0x410]       	mem=0x00000000582ef5c0
0x565902de	'test_x32_c'!0x12de	push  	0x400                         	
0x565902e3	'test_x32_c'!0x12e3	lea   	eax, [ebp - 0x40c]            	eax=0x00000000ffb13edc
0x565902e9	'test_x32_c'!0x12e9	push  	eax                           	eax=0x00000000ffb13edc
0x565902ea	'test_x32_c'!0x12ea	call  	0xfffffd67                    	eax=0x00000000ffb13edc ebx=0x0000000056592fb0 ecx=0x0000000072702f00 edx=0x000000002c2c2c2c esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb13ebc
0x56590050	'test_x32_c'!0x1050	jmp   	dword ptr [ebx + 0x14]        	mem=0x00000000f7d5b100
0xf7d5b100	'libc.so.6'!0x76100	_IO_fgets
0x565902ef	'test_x32_c'!0x12ef	add   	esp, 0x10                     	esp=0x00000000ffb13ed0 SF=0x1 ZF=0x0 PF=0x0
0x565902f2	'test_x32_c'!0x12f2	sub   	esp, 0xc                      	esp=0x00000000ffb13ec4 AF=0x1
0x565902f5	'test_x32_c'!0x12f5	push  	dword ptr [ebp - 0x410]       	mem=0x00000000582ef5c0
0x565902fb	'test_x32_c'!0x12fb	call  	0xfffffd66                    	eax=0x00000000ffb13edc ebx=0x0000000056592fb0 ecx=0x0000000000000000 edx=0x00000000582ef658 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb13ebc
0x56590060	'test_x32_c'!0x1060	jmp   	dword ptr [ebx + 0x18]        	mem=0x00000000f7d5a7a0
0xf7d5a7a0	'libc.so.6'!0x757a0	fclose
0x56590300	'test_x32_c'!0x1300	add   	esp, 0x10                     	esp=0x00000000ffb13ed0 PF=0x0
0x56590303	'test_x32_c'!0x1303	mov   	eax, 0                        	eax=0x0000000000000000
0x56590308	'test_x32_c'!0x1308	mov   	edx, dword ptr [ebp - 0xc]    	edx=0x0000000048d6e200
0x5659030b	'test_x32_c'!0x130b	sub   	edx, dword ptr gs:[0x14]      	edx=0x0000000000000000 SF=0x0 ZF=0x1 PF=0x1
0x56590312	'test_x32_c'!0x1312	je    	8                             	
0x56590319	'test_x32_c'!0x1319	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x0000000056592fb0
0x5659031c	'test_x32_c'!0x131c	leave 	                              	
0x5659031d	'test_x32_c'!0x131d	ret   	                              	
0x565903a1	'test_x32_c'!0x13a1	call  	0xfffffe7d                    	eax=0x0000000000000000 ebx=0x0000000056592fb0 ecx=0x00000000ffffffb8 edx=0x0000000000000000 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb14408 esp=0x00000000ffb142ec
0x5659021d	'test_x32_c'!0x121d	push  	ebp                           	ebp=0x00000000ffb14408
0x5659021e	'test_x32_c'!0x121e	mov   	ebp, esp                      	ebp=0x00000000ffb142e8
0x56590220	'test_x32_c'!0x1220	push  	ebx                           	ebx=0x0000000056592fb0
0x56590221	'test_x32_c'!0x1221	sub   	esp, 4                        	esp=0x00000000ffb142e0 SF=0x1 ZF=0x0 PF=0x0
0x56590224	'test_x32_c'!0x1224	call  	0xfffffefd                    	eax=0x0000000000000000 ebx=0x0000000056592fb0 ecx=0x00000000ffffffb8 edx=0x0000000000000000 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb142dc
0x56590120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x0000000056590229
0x56590123	'test_x32_c'!0x1123	ret   	                              	
0x56590229	'test_x32_c'!0x1229	add   	ebx, 0x2d87                   	ebx=0x0000000056592fb0 SF=0x0 AF=0x1
0x5659022f	'test_x32_c'!0x122f	push  	0                             	
0x56590231	'test_x32_c'!0x1231	push  	0                             	
0x56590233	'test_x32_c'!0x1233	push  	0                             	
0x56590235	'test_x32_c'!0x1235	push  	0                             	
0x56590237	'test_x32_c'!0x1237	call  	0xfffffe9a                    	eax=0x0000000000000000 ebx=0x0000000056592fb0 ecx=0x00000000ffffffb8 edx=0x0000000000000000 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb142cc
0x565900d0	'test_x32_c'!0x10d0	jmp   	dword ptr [ebx + 0x34]        	mem=0x00000000f7e050e0
0xf7e050e0	'libc.so.6'!0x1200e0	ptrace
0x5659023c	'test_x32_c'!0x123c	add   	esp, 0x10                     	esp=0x00000000ffb142e0 PF=0x0
0x5659023f	'test_x32_c'!0x123f	cmp   	eax, -1                       	eax=0x00000000ffffffff SF=0x0 ZF=0x1 PF=0x1
0x56590242	'test_x32_c'!0x1242	jne   	0x1f                          	
0x56590244	'test_x32_c'!0x1244	sub   	esp, 0xc                      	esp=0x00000000ffb142d4 SF=0x1 ZF=0x0 AF=0x1
0x56590247	'test_x32_c'!0x1247	lea   	eax, [ebx - 0x1fa8]           	eax=0x0000000056591008
0x5659024d	'test_x32_c'!0x124d	push  	eax                           	eax=0x0000000056591008
0x5659024e	'test_x32_c'!0x124e	call  	0xfffffe43                    	eax=0x0000000056591008 ebx=0x0000000056592fb0 ecx=0x00000000f7f2e500 edx=0x0000000000000000 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb142cc
0x56590090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0x00000000f7d5d140
0xf7d5d140	'libc.so.6'!0x78140	_IO_puts
0x56590253	'test_x32_c'!0x1253	add   	esp, 0x10                     	esp=0x00000000ffb142e0 SF=0x1 ZF=0x0 PF=0x0
0x56590256	'test_x32_c'!0x1256	sub   	esp, 0xc                      	esp=0x00000000ffb142d4 PF=0x1 AF=0x1
0x56590259	'test_x32_c'!0x1259	push  	1                             	
0x5659025b	'test_x32_c'!0x125b	call  	0xfffffe46                    	eax=0x0000000000000013 ebx=0x0000000056592fb0 ecx=0x00000000f7f178a0 edx=0x0000000000000000 esi=0x00000000ffb144dc edi=0x00000000f7f68b60 ebp=0x00000000ffb142e8 esp=0x00000000ffb142cc
0x565900a0	'test_x32_c'!0x10a0	jmp   	dword ptr [ebx + 0x28]        	mem=0x00000000f7d23bd0
0xf7d23bd0	'libc.so.6'!0x3ebd0	exit  
0x565901c0	'test_x32_c'!0x11c0	endbr32	                              	
0x565901c4	'test_x32_c'!0x11c4	push  	ebp                           	ebp=0x00000000ffb14268
0x565901c5	'test_x32_c'!0x11c5	mov   	ebp, esp                      	ebp=0x00000000ffb141e8
0x565901c7	'test_x32_c'!0x11c7	push  	ebx                           	ebx=0x0000000056592eb4
0x565901c8	'test_x32_c'!0x11c8	call  	0xffffff59                    	eax=0x0000000000000001 ebx=0x0000000056592eb4 ecx=0x00000000ffb14210 edx=0x0000000000000000 esi=0x0000000056592eb4 edi=0x00000000f7f69a20 ebp=0x00000000ffb141e8 esp=0x00000000ffb141e0
0x56590120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x00000000565901cd
0x56590123	'test_x32_c'!0x1123	ret   	                              	
0x565901cd	'test_x32_c'!0x11cd	add   	ebx, 0x2de3                   	ebx=0x0000000056592fb0 AF=0x1
0x565901d3	'test_x32_c'!0x11d3	sub   	esp, 4                        	esp=0x00000000ffb141e0 SF=0x1 AF=0x0
0x565901d6	'test_x32_c'!0x11d6	cmp   	byte ptr [ebx + 0x58], 0      	mem=0x0000000000000000 SF=0x0 ZF=0x1 PF=0x1
0x565901dd	'test_x32_c'!0x11dd	jne   	0x2a                          	
0x565901df	'test_x32_c'!0x11df	mov   	eax, dword ptr [ebx + 0x40]   	eax=0x00000000f7d23340
0x565901e5	'test_x32_c'!0x11e5	test  	eax, eax                      	eax=0x00000000f7d23340 SF=0x1 ZF=0x0 PF=0x0
0x565901e7	'test_x32_c'!0x11e7	je    	0x14                          	
0x565901e9	'test_x32_c'!0x11e9	sub   	esp, 0xc                      	esp=0x00000000ffb141d4 PF=0x1 AF=0x1
0x565901ec	'test_x32_c'!0x11ec	push  	dword ptr [ebx + 0x54]        	mem=0x0000000056593004
0x565901f2	'test_x32_c'!0x11f2	call  	0xfffffeef                    	eax=0x00000000f7d23340 ebx=0x0000000056592fb0 ecx=0x00000000ffb14210 edx=0x0000000000000000 esi=0x0000000056592eb4 edi=0x00000000f7f69a20 ebp=0x00000000ffb141e8 esp=0x00000000ffb141cc
0x565900e0	'test_x32_c'!0x10e0	jmp   	dword ptr [ebx + 0x40]        	mem=0x00000000f7d23340
0xf7d23340	'libc.so.6'!0x3e340	__cxa_finalize
0x565901f7	'test_x32_c'!0x11f7	add   	esp, 0x10                     	esp=0x00000000ffb141e0
0x565901fa	'test_x32_c'!0x11fa	call  	0xffffff37                    	eax=0x0000000000000001 ebx=0x0000000056592fb0 ecx=0x00000000f7f173c8 edx=0x0000000000000001 esi=0x0000000056592eb4 edi=0x00000000f7f69a20 ebp=0x00000000ffb141e8 esp=0x00000000ffb141dc
0x56590130	'test_x32_c'!0x1130	call  	0xea                          	eax=0x0000000000000001 ebx=0x0000000056592fb0 ecx=0x00000000f7f173c8 edx=0x0000000000000001 esi=0x0000000056592eb4 edi=0x00000000f7f69a20 ebp=0x00000000ffb141e8 esp=0x00000000ffb141d8
0x56590219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x0000000056590135
0x5659021c	'test_x32_c'!0x121c	ret   	                              	
0x56590135	'test_x32_c'!0x1135	add   	edx, 0x2e7b                   	edx=0x0000000056592fb0 SF=0x0 AF=0x1
0x5659013b	'test_x32_c'!0x113b	lea   	ecx, [edx + 0x58]             	ecx=0x0000000056593008
0x56590141	'test_x32_c'!0x1141	lea   	eax, [edx + 0x58]             	eax=0x0000000056593008
0x56590147	'test_x32_c'!0x1147	cmp   	eax, ecx                      	eax=0x0000000056593008 ZF=0x1 PF=0x1 AF=0x0
0x56590149	'test_x32_c'!0x1149	je    	0x20                          	
0x56590168	'test_x32_c'!0x1168	ret   	                              	
0x565901ff	'test_x32_c'!0x11ff	mov   	byte ptr [ebx + 0x58], 1      	mem=0x0000000000000001
0x56590206	'test_x32_c'!0x1206	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x0000000056592eb4
0x56590209	'test_x32_c'!0x1209	leave 	                              	
0x5659020a	'test_x32_c'!0x120a	ret   	                              	
0xf7f360e2	'ld-linux.so.2'!0x10e2	unknown_lib_function(ld-linux.so.2)
0x565903f4	'test_x32_c'!0x13f4	push  	ebx                           	ebx=0x0000000000000004
0x565903f5	'test_x32_c'!0x13f5	sub   	esp, 8                        	esp=0x00000000ffb141f0 SF=0x1 PF=0x1
0x565903f8	'test_x32_c'!0x13f8	call  	0xfffffd29                    	eax=0x00000000565903f4 ebx=0x0000000000000004 ecx=0x0000000056593008 edx=0x0000000056592ec8 esi=0x00000000f7f69a20 edi=0x0000000000000001 ebp=0x00000000ffb14268 esp=0x00000000ffb141ec
0x56590120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x00000000565903fd
0x56590123	'test_x32_c'!0x1123	ret   	                              	
0x565903fd	'test_x32_c'!0x13fd	add   	ebx, 0x2bb3                   	ebx=0x0000000056592fb0 SF=0x0 PF=0x0 AF=0x1
0x56590403	'test_x32_c'!0x1403	add   	esp, 8                        	esp=0x00000000ffb141f8 SF=0x1 AF=0x0
0x56590406	'test_x32_c'!0x1406	pop   	ebx                           	ebx=0x0000000000000004
0x56590407	'test_x32_c'!0x1407	ret   	                              	
0xf7f3a079	'ld-linux.so.2'!0x5079	unknown_lib_function(ld-linux.so.2)
