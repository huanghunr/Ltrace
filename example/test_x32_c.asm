eax      0xf7f80a20    ebx      0xf7f7ffe8    ecx      0xf7f80d28
edx      0xf7f50e80    esi      0xffcdc10c    edi      0x565860f0
ebp      0x00000000    esp      0xffcdc100    eip      0x565860f0
eflags   0x00010286    cs       0x00000023    ss       0x0000002b
ds       0x0000002b    es       0x0000002b    fs       0x00000000
gs       0x00000063
ZF=0x0 SF=0x1 CF=0x0 OF=0x0 PF=0x1 AF=0x0
mm0=0x0    st0=0.0    mm1=0x0    st1=0.0    mm2=0x0    st2=0.0    mm3=0x0    st3=0.0    mm4=0x0    st4=0.0    mm5=0x0    st5=0.0    mm6=0x0    st6=0.0    mm7=0x0    st7=0.0    xmm0=0x0    ymm0=0x0    xmm1=0x0    ymm1=0x0    xmm2=0x0    ymm2=0x0    xmm3=0x0    ymm3=0x0    xmm4=0x0    ymm4=0x0    xmm5=0x0    ymm5=0x0    xmm6=0x0    ymm6=0x0    xmm7=0x0    ymm7=0x0    
-----------
0x565860f0	'test_x32_c'!0x10f0	xor   	ebp, ebp                      	ebp=0x00000000 SF=0x0 ZF=0x1
0x565860f2	'test_x32_c'!0x10f2	pop   	esi                           	esi=0x00000001
0x565860f3	'test_x32_c'!0x10f3	mov   	ecx, esp                      	ecx=0xffcdc104
0x565860f5	'test_x32_c'!0x10f5	and   	esp, 0xfffffff0               	esp=0xffcdc100 SF=0x1 ZF=0x0
0x565860f8	'test_x32_c'!0x10f8	push  	eax                           	eax=0xf7f80a20
0x565860f9	'test_x32_c'!0x10f9	push  	esp                           	esp=0xffcdc0f8
0x565860fa	'test_x32_c'!0x10fa	push  	edx                           	edx=0xf7f50e80
0x565860fb	'test_x32_c'!0x10fb	call  	0x1e                          	eax=0xf7f80a20 ebx=0xf7f7ffe8 ecx=0xffcdc104 edx=0xf7f50e80 esi=0x00000001 edi=0x565860f0 ebp=0x00000000 esp=0xffcdc0f0
0x56586118	'test_x32_c'!0x1118	mov   	ebx, dword ptr [esp]          	ebx=0x56586100
0x5658611b	'test_x32_c'!0x111b	ret   	                              	
0x56586100	'test_x32_c'!0x1100	add   	ebx, 0x2eb0                   	ebx=0x56588fb0 SF=0x0 PF=0x0
0x56586106	'test_x32_c'!0x1106	push  	0                             	
0x56586108	'test_x32_c'!0x1108	push  	0                             	
0x5658610a	'test_x32_c'!0x110a	push  	ecx                           	ecx=0xffcdc104
0x5658610b	'test_x32_c'!0x110b	push  	esi                           	esi=0x00000001
0x5658610c	'test_x32_c'!0x110c	push  	dword ptr [ebx + 0x48]        	mem=0x5658631e
0x56586112	'test_x32_c'!0x1112	call  	0xffffff1f                    	eax=0xf7f80a20 ebx=0x56588fb0 ecx=0xffcdc104 edx=0xf7f50e80 esi=0x00000001 edi=0x565860f0 ebp=0x00000000 esp=0xffcdc0dc
0x56586030	'test_x32_c'!0x1030	jmp   	dword ptr [ebx + 0xc]         	mem=0xf7d20cf0
0xf7d20cf0	'libc.so.6'!0x24cf0	__libc_start_main
0x56586000	'test_x32_c'!0x1000	push  	ebx                           	ebx=0xf7f2ce34
0x56586001	'test_x32_c'!0x1001	sub   	esp, 8                        	esp=0xffcdc090 SF=0x1
0x56586004	'test_x32_c'!0x1004	call  	0x11d                         	eax=0xffcdc10c ebx=0xf7f2ce34 ecx=0x56586000 edx=0xf7f80000 esi=0xf7f80a20 edi=0xf7f7fb60 ebp=0x00000000 esp=0xffcdc08c
0x56586120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x56586009
0x56586123	'test_x32_c'!0x1123	ret   	                              	
0x56586009	'test_x32_c'!0x1009	add   	ebx, 0x2fa7                   	ebx=0x56588fb0 SF=0x0 PF=0x0 AF=0x1
0x5658600f	'test_x32_c'!0x100f	mov   	eax, dword ptr [ebx + 0x44]   	eax=0x00000000
0x56586015	'test_x32_c'!0x1015	test  	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x56586017	'test_x32_c'!0x1017	je    	5                             	
0x5658601b	'test_x32_c'!0x101b	add   	esp, 8                        	esp=0xffcdc098 SF=0x1 ZF=0x0 PF=0x0
0x5658601e	'test_x32_c'!0x101e	pop   	ebx                           	ebx=0xf7f2ce34
0x5658601f	'test_x32_c'!0x101f	ret   	                              	
0xf7d20da4	'libc.so.6'!0x24da4	unknown_lib_function(libc.so.6)
0x56586210	'test_x32_c'!0x1210	endbr32	                              	
0x56586214	'test_x32_c'!0x1214	jmp   	0xffffff5d                    	
0x56586170	'test_x32_c'!0x1170	call  	0xaa                          	eax=0xffcdc10c ebx=0xf7f2ce34 ecx=0x56588eb4 edx=0xf7f80000 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0x56588eb0 esp=0xffcdc098
0x56586219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x56586175
0x5658621c	'test_x32_c'!0x121c	ret   	                              	
0x56586175	'test_x32_c'!0x1175	add   	edx, 0x2e3b                   	edx=0x56588fb0 SF=0x0 PF=0x0
0x5658617b	'test_x32_c'!0x117b	push  	ebp                           	ebp=0x56588eb0
0x5658617c	'test_x32_c'!0x117c	mov   	ebp, esp                      	ebp=0xffcdc098
0x5658617e	'test_x32_c'!0x117e	push  	ebx                           	ebx=0xf7f2ce34
0x5658617f	'test_x32_c'!0x117f	lea   	ecx, [edx + 0x58]             	ecx=0x56589008
0x56586185	'test_x32_c'!0x1185	lea   	eax, [edx + 0x58]             	eax=0x56589008
0x5658618b	'test_x32_c'!0x118b	sub   	esp, 4                        	esp=0xffcdc090 SF=0x1 PF=0x1 AF=0x0
0x5658618e	'test_x32_c'!0x118e	sub   	eax, ecx                      	eax=0x00000000 SF=0x0 ZF=0x1
0x56586190	'test_x32_c'!0x1190	mov   	ebx, eax                      	ebx=0x00000000
0x56586192	'test_x32_c'!0x1192	shr   	eax, 0x1f                     	eax=0x00000000
0x56586195	'test_x32_c'!0x1195	sar   	ebx, 2                        	ebx=0x00000000
0x56586198	'test_x32_c'!0x1198	add   	eax, ebx                      	eax=0x00000000
0x5658619a	'test_x32_c'!0x119a	sar   	eax, 1                        	eax=0x00000000
0x5658619c	'test_x32_c'!0x119c	je    	0x17                          	
0x565861b2	'test_x32_c'!0x11b2	mov   	ebx, dword ptr [ebp - 4]      	ebx=0xf7f2ce34
0x565861b5	'test_x32_c'!0x11b5	leave 	                              	
0x565861b6	'test_x32_c'!0x11b6	ret   	                              	
0xf7d20e07	'libc.so.6'!0x24e07	unknown_lib_function(libc.so.6)
0x5658631e	'test_x32_c'!0x131e	lea   	ecx, [esp + 4]                	ecx=0xffcdc050
0x56586322	'test_x32_c'!0x1322	and   	esp, 0xfffffff0               	esp=0xffcdc040 SF=0x1 ZF=0x0 PF=0x0
0x56586325	'test_x32_c'!0x1325	push  	dword ptr [ecx - 4]           	mem=0xf7d20cb9
0x56586328	'test_x32_c'!0x1328	push  	ebp                           	ebp=0x00000000
0x56586329	'test_x32_c'!0x1329	mov   	ebp, esp                      	ebp=0xffcdc038
0x5658632b	'test_x32_c'!0x132b	push  	ebx                           	ebx=0xf7f2ce34
0x5658632c	'test_x32_c'!0x132c	push  	ecx                           	ecx=0xffcdc050
0x5658632d	'test_x32_c'!0x132d	sub   	esp, 0x110                    	esp=0xffcdbf20
0x56586333	'test_x32_c'!0x1333	call  	0xfffffdee                    	eax=0x5658631e ebx=0xf7f2ce34 ecx=0xffcdc050 edx=0xffcdc070 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdc038 esp=0xffcdbf1c
0x56586120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x56586338
0x56586123	'test_x32_c'!0x1123	ret   	                              	
0x56586338	'test_x32_c'!0x1338	add   	ebx, 0x2c78                   	ebx=0x56588fb0 SF=0x0 AF=0x1
0x5658633e	'test_x32_c'!0x133e	mov   	eax, dword ptr gs:[0x14]      	eax=0x42299200
0x56586344	'test_x32_c'!0x1344	mov   	dword ptr [ebp - 0xc], eax    	mem=0x42299200
0x56586347	'test_x32_c'!0x1347	xor   	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x56586349	'test_x32_c'!0x1349	sub   	esp, 0xc                      	esp=0xffcdbf14 SF=0x1 ZF=0x0 AF=0x1
0x5658634c	'test_x32_c'!0x134c	lea   	eax, [ebx - 0x1f64]           	eax=0x5658704c
0x56586352	'test_x32_c'!0x1352	push  	eax                           	eax=0x5658704c
0x56586353	'test_x32_c'!0x1353	call  	0xfffffd3e                    	eax=0x5658704c ebx=0x56588fb0 ecx=0xffcdc050 edx=0xffcdc070 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdc038 esp=0xffcdbf0c
0x56586090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0xf7d74140
0xf7d74140	'libc.so.6'!0x78140	_IO_puts
0x56586358	'test_x32_c'!0x1358	add   	esp, 0x10                     	esp=0xffcdbf20 SF=0x1 ZF=0x0 PF=0x0
0x5658635b	'test_x32_c'!0x135b	sub   	esp, 8                        	esp=0xffcdbf18 PF=0x1 AF=0x1
0x5658635e	'test_x32_c'!0x135e	lea   	eax, [ebp - 0x10c]            	eax=0xffcdbf2c
0x56586364	'test_x32_c'!0x1364	push  	eax                           	eax=0xffcdbf2c
0x56586365	'test_x32_c'!0x1365	lea   	eax, [ebx - 0x1f44]           	eax=0x5658706c
0x5658636b	'test_x32_c'!0x136b	push  	eax                           	eax=0x5658706c
0x5658636c	'test_x32_c'!0x136c	call  	0xfffffd55                    	eax=0x5658706c ebx=0x56588fb0 ecx=0xf7f2e8a0 edx=0x00000000 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdc038 esp=0xffcdbf0c
0x565860c0	'test_x32_c'!0x10c0	jmp   	dword ptr [ebx + 0x30]        	mem=0xf7d53bd0
0xf7d53bd0	'libc.so.6'!0x57bd0	__isoc99_scanf
0x56586371	'test_x32_c'!0x1371	add   	esp, 0x10                     	esp=0xffcdbf20 PF=0x0
0x56586374	'test_x32_c'!0x1374	cmp   	eax, 1                        	eax=0x00000001 SF=0x0 ZF=0x1 PF=0x1
0x56586377	'test_x32_c'!0x1377	je    	0x26                          	
0x5658639c	'test_x32_c'!0x139c	call  	0xfffffecf                    	eax=0x00000001 ebx=0x56588fb0 ecx=0x00000000 edx=0xf7f45500 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdc038 esp=0xffcdbf1c
0x5658626a	'test_x32_c'!0x126a	push  	ebp                           	ebp=0xffcdc038
0x5658626b	'test_x32_c'!0x126b	mov   	ebp, esp                      	ebp=0xffcdbf18
0x5658626d	'test_x32_c'!0x126d	push  	ebx                           	ebx=0x56588fb0
0x5658626e	'test_x32_c'!0x126e	sub   	esp, 0x414                    	esp=0xffcdbb00 SF=0x1 ZF=0x0
0x56586274	'test_x32_c'!0x1274	call  	0xfffffead                    	eax=0x00000001 ebx=0x56588fb0 ecx=0x00000000 edx=0xf7f45500 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbafc
0x56586120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x56586279
0x56586123	'test_x32_c'!0x1123	ret   	                              	
0x56586279	'test_x32_c'!0x1279	add   	ebx, 0x2d37                   	ebx=0x56588fb0 SF=0x0 PF=0x0 AF=0x1
0x5658627f	'test_x32_c'!0x127f	mov   	eax, dword ptr gs:[0x14]      	eax=0x42299200
0x56586285	'test_x32_c'!0x1285	mov   	dword ptr [ebp - 0xc], eax    	mem=0x42299200
0x56586288	'test_x32_c'!0x1288	xor   	eax, eax                      	eax=0x00000000 ZF=0x1 PF=0x1 AF=0x0
0x5658628a	'test_x32_c'!0x128a	sub   	esp, 8                        	esp=0xffcdbaf8 SF=0x1 ZF=0x0 PF=0x0 AF=0x1
0x5658628d	'test_x32_c'!0x128d	lea   	eax, [ebx - 0x1f95]           	eax=0x5658701b
0x56586293	'test_x32_c'!0x1293	push  	eax                           	eax=0x5658701b
0x56586294	'test_x32_c'!0x1294	lea   	eax, [ebx - 0x1f93]           	eax=0x5658701d
0x5658629a	'test_x32_c'!0x129a	push  	eax                           	eax=0x5658701d
0x5658629b	'test_x32_c'!0x129b	call  	0xfffffe16                    	eax=0x5658701d ebx=0x56588fb0 ecx=0x00000000 edx=0xf7f45500 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbaec
0x565860b0	'test_x32_c'!0x10b0	jmp   	dword ptr [ebx + 0x2c]        	mem=0xf7d72410
0xf7d72410	'libc.so.6'!0x76410	_IO_fopen
0x565862a0	'test_x32_c'!0x12a0	add   	esp, 0x10                     	esp=0xffcdbb00 PF=0x1
0x565862a3	'test_x32_c'!0x12a3	mov   	dword ptr [ebp - 0x410], eax  	mem=0x574355c0
0x565862a9	'test_x32_c'!0x12a9	cmp   	dword ptr [ebp - 0x410], 0    	mem=0x574355c0 SF=0x0
0x565862b0	'test_x32_c'!0x12b0	jne   	0x26                          	
0x565862d5	'test_x32_c'!0x12d5	sub   	esp, 4                        	esp=0xffcdbafc SF=0x1 AF=0x1
0x565862d8	'test_x32_c'!0x12d8	push  	dword ptr [ebp - 0x410]       	mem=0x574355c0
0x565862de	'test_x32_c'!0x12de	push  	0x400                         	
0x565862e3	'test_x32_c'!0x12e3	lea   	eax, [ebp - 0x40c]            	eax=0xffcdbb0c
0x565862e9	'test_x32_c'!0x12e9	push  	eax                           	eax=0xffcdbb0c
0x565862ea	'test_x32_c'!0x12ea	call  	0xfffffd67                    	eax=0xffcdbb0c ebx=0x56588fb0 ecx=0x72702f00 edx=0x2c2c2c2c esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbaec
0x56586050	'test_x32_c'!0x1050	jmp   	dword ptr [ebx + 0x14]        	mem=0xf7d72100
0xf7d72100	'libc.so.6'!0x76100	_IO_fgets
0x565862ef	'test_x32_c'!0x12ef	add   	esp, 0x10                     	esp=0xffcdbb00 SF=0x1 ZF=0x0
0x565862f2	'test_x32_c'!0x12f2	sub   	esp, 0xc                      	esp=0xffcdbaf4 PF=0x0 AF=0x1
0x565862f5	'test_x32_c'!0x12f5	push  	dword ptr [ebp - 0x410]       	mem=0x574355c0
0x565862fb	'test_x32_c'!0x12fb	call  	0xfffffd66                    	eax=0xffcdbb0c ebx=0x56588fb0 ecx=0x00000000 edx=0x57435658 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbaec
0x56586060	'test_x32_c'!0x1060	jmp   	dword ptr [ebx + 0x18]        	mem=0xf7d717a0
0xf7d717a0	'libc.so.6'!0x757a0	fclose
0x56586300	'test_x32_c'!0x1300	add   	esp, 0x10                     	esp=0xffcdbb00
0x56586303	'test_x32_c'!0x1303	mov   	eax, 0                        	eax=0x00000000
0x56586308	'test_x32_c'!0x1308	mov   	edx, dword ptr [ebp - 0xc]    	edx=0x42299200
0x5658630b	'test_x32_c'!0x130b	sub   	edx, dword ptr gs:[0x14]      	edx=0x00000000 SF=0x0 ZF=0x1
0x56586312	'test_x32_c'!0x1312	je    	8                             	
0x56586319	'test_x32_c'!0x1319	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x56588fb0
0x5658631c	'test_x32_c'!0x131c	leave 	                              	
0x5658631d	'test_x32_c'!0x131d	ret   	                              	
0x565863a1	'test_x32_c'!0x13a1	call  	0xfffffe7d                    	eax=0x00000000 ebx=0x56588fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdc038 esp=0xffcdbf1c
0x5658621d	'test_x32_c'!0x121d	push  	ebp                           	ebp=0xffcdc038
0x5658621e	'test_x32_c'!0x121e	mov   	ebp, esp                      	ebp=0xffcdbf18
0x56586220	'test_x32_c'!0x1220	push  	ebx                           	ebx=0x56588fb0
0x56586221	'test_x32_c'!0x1221	sub   	esp, 4                        	esp=0xffcdbf10 SF=0x1 ZF=0x0 PF=0x0
0x56586224	'test_x32_c'!0x1224	call  	0xfffffefd                    	eax=0x00000000 ebx=0x56588fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbf0c
0x56586120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x56586229
0x56586123	'test_x32_c'!0x1123	ret   	                              	
0x56586229	'test_x32_c'!0x1229	add   	ebx, 0x2d87                   	ebx=0x56588fb0 SF=0x0 AF=0x1
0x5658622f	'test_x32_c'!0x122f	push  	0                             	
0x56586231	'test_x32_c'!0x1231	push  	0                             	
0x56586233	'test_x32_c'!0x1233	push  	0                             	
0x56586235	'test_x32_c'!0x1235	push  	0                             	
0x56586237	'test_x32_c'!0x1237	call  	0xfffffe9a                    	eax=0x00000000 ebx=0x56588fb0 ecx=0xffffffb8 edx=0x00000000 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbefc
0x565860d0	'test_x32_c'!0x10d0	jmp   	dword ptr [ebx + 0x34]        	mem=0xf7e1c0e0
0xf7e1c0e0	'libc.so.6'!0x1200e0	ptrace
0x5658623c	'test_x32_c'!0x123c	add   	esp, 0x10                     	esp=0xffcdbf10 PF=0x0
0x5658623f	'test_x32_c'!0x123f	cmp   	eax, -1                       	eax=0xffffffff SF=0x0 ZF=0x1 PF=0x1
0x56586242	'test_x32_c'!0x1242	jne   	0x1f                          	
0x56586244	'test_x32_c'!0x1244	sub   	esp, 0xc                      	esp=0xffcdbf04 SF=0x1 ZF=0x0 PF=0x0 AF=0x1
0x56586247	'test_x32_c'!0x1247	lea   	eax, [ebx - 0x1fa8]           	eax=0x56587008
0x5658624d	'test_x32_c'!0x124d	push  	eax                           	eax=0x56587008
0x5658624e	'test_x32_c'!0x124e	call  	0xfffffe43                    	eax=0x56587008 ebx=0x56588fb0 ecx=0xf7f45500 edx=0x00000000 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbefc
0x56586090	'test_x32_c'!0x1090	jmp   	dword ptr [ebx + 0x24]        	mem=0xf7d74140
0xf7d74140	'libc.so.6'!0x78140	_IO_puts
0x56586253	'test_x32_c'!0x1253	add   	esp, 0x10                     	esp=0xffcdbf10 SF=0x1 ZF=0x0 PF=0x0
0x56586256	'test_x32_c'!0x1256	sub   	esp, 0xc                      	esp=0xffcdbf04 AF=0x1
0x56586259	'test_x32_c'!0x1259	push  	1                             	
0x5658625b	'test_x32_c'!0x125b	call  	0xfffffe46                    	eax=0x00000013 ebx=0x56588fb0 ecx=0xf7f2e8a0 edx=0x00000000 esi=0xffcdc10c edi=0xf7f7fb60 ebp=0xffcdbf18 esp=0xffcdbefc
0x565860a0	'test_x32_c'!0x10a0	jmp   	dword ptr [ebx + 0x28]        	mem=0xf7d3abd0
0xf7d3abd0	'libc.so.6'!0x3ebd0	exit  
0x565861c0	'test_x32_c'!0x11c0	endbr32	                              	
0x565861c4	'test_x32_c'!0x11c4	push  	ebp                           	ebp=0xffcdbe98
0x565861c5	'test_x32_c'!0x11c5	mov   	ebp, esp                      	ebp=0xffcdbe18
0x565861c7	'test_x32_c'!0x11c7	push  	ebx                           	ebx=0x56588eb4
0x565861c8	'test_x32_c'!0x11c8	call  	0xffffff59                    	eax=0x00000001 ebx=0x56588eb4 ecx=0xffcdbe40 edx=0x00000000 esi=0x56588eb4 edi=0xf7f80a20 ebp=0xffcdbe18 esp=0xffcdbe10
0x56586120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565861cd
0x56586123	'test_x32_c'!0x1123	ret   	                              	
0x565861cd	'test_x32_c'!0x11cd	add   	ebx, 0x2de3                   	ebx=0x56588fb0 AF=0x1
0x565861d3	'test_x32_c'!0x11d3	sub   	esp, 4                        	esp=0xffcdbe10 SF=0x1 AF=0x0
0x565861d6	'test_x32_c'!0x11d6	cmp   	byte ptr [ebx + 0x58], 0      	mem=0x00000000 SF=0x0 ZF=0x1 PF=0x1
0x565861dd	'test_x32_c'!0x11dd	jne   	0x2a                          	
0x565861df	'test_x32_c'!0x11df	mov   	eax, dword ptr [ebx + 0x40]   	eax=0xf7d3a340
0x565861e5	'test_x32_c'!0x11e5	test  	eax, eax                      	eax=0xf7d3a340 SF=0x1 ZF=0x0 PF=0x0
0x565861e7	'test_x32_c'!0x11e7	je    	0x14                          	
0x565861e9	'test_x32_c'!0x11e9	sub   	esp, 0xc                      	esp=0xffcdbe04 AF=0x1
0x565861ec	'test_x32_c'!0x11ec	push  	dword ptr [ebx + 0x54]        	mem=0x56589004
0x565861f2	'test_x32_c'!0x11f2	call  	0xfffffeef                    	eax=0xf7d3a340 ebx=0x56588fb0 ecx=0xffcdbe40 edx=0x00000000 esi=0x56588eb4 edi=0xf7f80a20 ebp=0xffcdbe18 esp=0xffcdbdfc
0x565860e0	'test_x32_c'!0x10e0	jmp   	dword ptr [ebx + 0x40]        	mem=0xf7d3a340
0xf7d3a340	'libc.so.6'!0x3e340	__cxa_finalize
0x565861f7	'test_x32_c'!0x11f7	add   	esp, 0x10                     	esp=0xffcdbe10
0x565861fa	'test_x32_c'!0x11fa	call  	0xffffff37                    	eax=0x00000001 ebx=0x56588fb0 ecx=0xf7f2e3c8 edx=0x00000001 esi=0x56588eb4 edi=0xf7f80a20 ebp=0xffcdbe18 esp=0xffcdbe0c
0x56586130	'test_x32_c'!0x1130	call  	0xea                          	eax=0x00000001 ebx=0x56588fb0 ecx=0xf7f2e3c8 edx=0x00000001 esi=0x56588eb4 edi=0xf7f80a20 ebp=0xffcdbe18 esp=0xffcdbe08
0x56586219	'test_x32_c'!0x1219	mov   	edx, dword ptr [esp]          	edx=0x56586135
0x5658621c	'test_x32_c'!0x121c	ret   	                              	
0x56586135	'test_x32_c'!0x1135	add   	edx, 0x2e7b                   	edx=0x56588fb0 SF=0x0 AF=0x1
0x5658613b	'test_x32_c'!0x113b	lea   	ecx, [edx + 0x58]             	ecx=0x56589008
0x56586141	'test_x32_c'!0x1141	lea   	eax, [edx + 0x58]             	eax=0x56589008
0x56586147	'test_x32_c'!0x1147	cmp   	eax, ecx                      	eax=0x56589008 ZF=0x1 PF=0x1 AF=0x0
0x56586149	'test_x32_c'!0x1149	je    	0x20                          	
0x56586168	'test_x32_c'!0x1168	ret   	                              	
0x565861ff	'test_x32_c'!0x11ff	mov   	byte ptr [ebx + 0x58], 1      	mem=0x00000001
0x56586206	'test_x32_c'!0x1206	mov   	ebx, dword ptr [ebp - 4]      	ebx=0x56588eb4
0x56586209	'test_x32_c'!0x1209	leave 	                              	
0x5658620a	'test_x32_c'!0x120a	ret   	                              	
0xf7f4d0e2	'ld-linux.so.2'!0x10e2	unknown_lib_function(ld-linux.so.2)
0x565863f4	'test_x32_c'!0x13f4	push  	ebx                           	ebx=0x00000004
0x565863f5	'test_x32_c'!0x13f5	sub   	esp, 8                        	esp=0xffcdbe20 SF=0x1
0x565863f8	'test_x32_c'!0x13f8	call  	0xfffffd29                    	eax=0x565863f4 ebx=0x00000004 ecx=0x56589008 edx=0x56588ec8 esi=0xf7f80a20 edi=0x00000001 ebp=0xffcdbe98 esp=0xffcdbe1c
0x56586120	'test_x32_c'!0x1120	mov   	ebx, dword ptr [esp]          	ebx=0x565863fd
0x56586123	'test_x32_c'!0x1123	ret   	                              	
0x565863fd	'test_x32_c'!0x13fd	add   	ebx, 0x2bb3                   	ebx=0x56588fb0 SF=0x0 AF=0x1
0x56586403	'test_x32_c'!0x1403	add   	esp, 8                        	esp=0xffcdbe28 SF=0x1 PF=0x1 AF=0x0
0x56586406	'test_x32_c'!0x1406	pop   	ebx                           	ebx=0x00000004
0x56586407	'test_x32_c'!0x1407	ret   	                              	
0xf7f51079	'ld-linux.so.2'!0x5079	unknown_lib_function(ld-linux.so.2)
