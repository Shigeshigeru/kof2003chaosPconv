
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BITSWAP8(n, 														\
		bit07, bit06, bit05, bit04, bit03, bit02, bit01, bit00)	\
		(((((n) >> (bit07)) & 1) <<  7) | 			\
		 ((((n) >> (bit06)) & 1) <<  6) | 			\
		 ((((n) >> (bit05)) & 1) <<  5) | 			\
		 ((((n) >> (bit04)) & 1) <<  4) | 			\
		 ((((n) >> (bit03)) & 1) <<  3) | 			\
		 ((((n) >> (bit02)) & 1) <<  2) | 			\
		 ((((n) >> (bit01)) & 1) <<  1) | 			\
		 ((((n) >> (bit00)) & 1) <<  0))

#define BITSWAP16(n, 														\
				  bit15, bit14, bit13, bit12, bit11, bit10, bit09, bit08,	\
				  bit07, bit06, bit05, bit04, bit03, bit02, bit01, bit00)	\
		(((((n) >> (bit15)) & 1) << 15) | 									\
		 ((((n) >> (bit14)) & 1) << 14) | 									\
		 ((((n) >> (bit13)) & 1) << 13) | 									\
		 ((((n) >> (bit12)) & 1) << 12) | 									\
		 ((((n) >> (bit11)) & 1) << 11) | 									\
		 ((((n) >> (bit10)) & 1) << 10) | 									\
		 ((((n) >> (bit09)) & 1) <<  9) | 									\
		 ((((n) >> (bit08)) & 1) <<  8) | 									\
		 ((((n) >> (bit07)) & 1) <<  7) | 									\
		 ((((n) >> (bit06)) & 1) <<  6) | 									\
		 ((((n) >> (bit05)) & 1) <<  5) | 									\
		 ((((n) >> (bit04)) & 1) <<  4) | 									\
		 ((((n) >> (bit03)) & 1) <<  3) | 									\
		 ((((n) >> (bit02)) & 1) <<  2) | 									\
		 ((((n) >> (bit01)) & 1) <<  1) | 									\
		 ((((n) >> (bit00)) & 1) <<  0))
		 
static void decryptsvc(unsigned char *src)
{
	 const unsigned char xor1[0x20] = { 0x3b, 0x6a, 0xf7, 0xb7, 0xe8, 0xa9, 0x20, 0x99, 0x9f, 0x39, 0x34, 0x0c, 0xc3, 0x9a, 0xa5, 0xc8, 0xb8, 0x18, 0xce, 0x56, 0x94, 0x44, 0xe3, 0x7a, 0xf7, 0xdd, 0x42, 0xf0, 0x18, 0x60, 0x92, 0x9f };
	 const unsigned char xor2[0x20] = { 0x69, 0x0b, 0x60, 0xd6, 0x4f, 0x01, 0x40, 0x1a, 0x9f, 0x0b, 0xf0, 0x75, 0x58, 0x0e, 0x60, 0xb4, 0x14, 0x04, 0x20, 0xe4, 0xb9, 0x0d, 0x10, 0x89, 0xeb, 0x07, 0x30, 0x90, 0x50, 0x0e, 0x20, 0x26 };


	int i, ofst;
	unsigned char* dst = (unsigned char*)malloc(0x900000);

	for (i = 0; i < 0x100000; i++)
	{
		src[ 0x800000 + i ] ^= src[ 0x100002 | i ];
	}
		for( i = 0; i < 0x100000; i++)
	{
		src[ i ] ^= xor1[ (i % 0x20) ];
	}
	for (i = 0x100000; i < 0x800000; i++)
	{
		src[ i ] ^= xor2[ (i % 0x20) ];
     }
	for (i = 0x100000; i < 0x800000; i += 4) {
		unsigned short *rom16 = (unsigned short*)&src[i + 1];
		*rom16 = BITSWAP16( *rom16, 15, 14, 13, 12, 10, 11, 8, 9, 6, 7, 4, 5, 3, 2, 1, 0 );	}

	memcpy(dst, src, 0x800000);
	


	for (i = 0; i < 0x10; i++) {
		ofst = (i & 0xf0) + BITSWAP8((i & 0x0f), 7, 6, 5, 4, 2, 3, 0, 1);
		memcpy(&dst[i * 0x10000], &src[ofst * 0x10000], 0x10000);
	}

	for (i = 0x100000; i < 0x900000; i += 0x100) {
		ofst = (i & 0xf000ff) + ((i & 0x000f00) ^ 0x00a00)
			+ (BITSWAP8(((i & 0x0ff000) >> 12), 4, 5, 6, 7, 1, 0, 3, 2 ) << 12);
		memcpy(&dst[i], &src[ofst], 0x100);
	}
	memcpy (&src[0x000000], &dst[0x000000], 0x100000);
	memcpy (&src[0x100000], &dst[0x800000], 0x100000);
	memcpy (&src[0x200000], &dst[0x100000], 0x700000);
	free(dst);
}

static void encryptsvc(unsigned char *src)
{
	int i, ofst;

	unsigned char xor1[0x20] = {
		0x3b, 0x6a, 0xf7, 0xb7, 0xe8, 0xa9, 0x20, 0x99, 0x9f, 0x39, 0x34, 0x0c, 0xc3, 0x9a, 0xa5, 0xc8,
		0xb8, 0x18, 0xce, 0x56, 0x94, 0x44, 0xe3, 0x7a, 0xf7, 0xdd, 0x42, 0xf0, 0x18, 0x60, 0x92, 0x9f
	};

	unsigned char xor2[0x20] = {
		0x69, 0x0b, 0x60, 0xd6, 0x4f, 0x01, 0x40, 0x1a, 0x9f, 0x0b, 0xf0, 0x75, 0x58, 0x0e, 0x60, 0xb4,
		0x14, 0x04, 0x20, 0xe4, 0xb9, 0x0d, 0x10, 0x89, 0xeb, 0x07, 0x30, 0x90, 0x50, 0x0e, 0x20, 0x26
	};

	unsigned char *dst = (unsigned char*)malloc(0x900000);

	// copy everything to dst
        memcpy (&dst[0x000000], &src[0x000000], 0x100000);
        memcpy (&dst[0x800000], &src[0x100000], 0x100000);
        memcpy (&dst[0x100000], &src[0x200000], 0x700000);
        
       for( i = 0x100000; i < 0x900000; i += 0x100)
        {
                ofst = (i & 0xf000ff) + ((i & 0x000f00) ^ 0x00a00) + (BITSWAP8( ((i & 0x0ff000) >> 12), 4, 5, 6, 7, 1, 0, 3, 2 ) << 12);
                memcpy( &src[ i ], &dst[ ofst ], 0x100 );
        }

        for( i = 0; i < 0x0100000 / 0x10000; i++ )
        {
                ofst = (i & 0xf0) + BITSWAP8((i & 0x0f), 7, 6, 5, 4, 2, 3, 0, 1 );
                memcpy( &src[ i * 0x10000 ], &dst[ ofst * 0x10000 ], 0x10000 );
        }

        for( i = 0x100000; i < 0x800000; i += 4)
        {
		unsigned short *rom16 = (unsigned short*)&src[ i + 1 ];
		*rom16 = (BITSWAP8((*rom16&0xFF0)>>4, 6,7,4,5,2,3,0,1)<<4)|(*rom16&0xF00F);
	}

        for( i = 0x100000; i < 0x800000; i++)
        {
                src[ i ] ^= xor2[ (i % 0x20) ];
        }

        for( i = 0; i < 0x100000; i++)
        {
                src[ i ] ^= xor1[ (i % 0x20) ];
        }

        for (i = 0; i < 0x100000; i++)
        {
                src[ 0x800000 + i ] ^= src[ 0x100002 | i ];
        }
	free (dst);
}

//static void patch(unsigned char *src)
//{
//	int i;
//	unsigned char patch_2[0x12] = {
//		0x59, 0xF8, 0x2D, 0x0C, 0x00, 0x00, 0x59, 0xF8, 0x00, 0x66, 0x08, 0x00, 0x7C, 0x1B, 0x02, 0x00, 
//		0x59, 0xF8
//	};
//
//	*((unsigned short*)(src + 0x00C0)) = 0x4638;
//	*((unsigned short*)(src + 0x00C2)) = 0x5F50;
//	*((unsigned short*)(src + 0x0408)) = 0x4465;
//	*((unsigned short*)(src + 0x040A)) = 0x6320;
//	*((unsigned short*)(src + 0x040C)) = 0x3031;
//	*((unsigned short*)(src + 0x0412)) = 0x3133;
//	*((unsigned short*)(src + 0x0414)) = 0x3A34;
//	*((unsigned short*)(src + 0x0416)) = 0x3820;
//
//	memcpy (src + 0x1C6, src + 0x1B6, 0xE8);
//
//	for (i = 0; i < 0x12; i++)
//		src[0x1B4 + i] = patch_2[i];
//
//	for (i = 0; i < 0x100000; i+=2) // modify P data to use Zoom code in program
//	{
//		if (((src[i + 0] == 0xB9) || (src[i + 0] == 0xF9)) && ((src[i + 1]&0xf0) == 0x40) && (src[i + 2] == 0xC2))
//		{
//			src[i + 2] = 0x0F;
//			src[i + 5] += 0x80;
//		}
//
//		if ((i > 0xF95B0) && (i < 0xF9720))
//		{
//			if ((src[i + 0] == 0xC2) && (src[i + 1] == 0x00))
//			{
//				src[i + 0] = 0x0F;
//				src[i + 3] += 0x80;
//			}
//		}
//
//		if ((src[i + 0] == 0xC1) && (src[i + 2] == 0x80) && (src[i + 3] == 0xFF)) // more bios code stuff
//		{
//			src[i + 0] = 0x0F;
//			src[i + 2] = 0x00;
//			src[i + 3] = 0xC0;
//		}
//	}
//}

void print_info(int io)
{
	if (io == 0) // 如果是?入文件?查?段
	{
		printf("These files are required as input:\n\n");
		printf("271-p1.bin\tsize 4194304\tcrc B9DA070C \n\t\tsha1 1A26325AF142A4DD221C336061761468598C4634\n\n");
		printf("271-p2.bin\tsize 4194304\tcrc DA3118C4 \n\t\tsha1 582E4F44F03276ADECB7B2848D3B96BF6DA57F1E\n\n");
		printf("271-p3.bin\tsize 1048576\n\n"); // 增加p3文件的信息
	}

	if (io == 1) // 如果是?出文件?查?段
	{
		printf("\nThese files should have been produced:\n\n");
		printf("271-p1c.bin\tsize 4194304\tcrc 530ECC14\n\t\tsha1 812CF7E9902AF3F5E9E330B7C05C2171B139AD2B\n\n");
		printf("271-p2c.bin\tsize 4194304\tcrc FD568DA9\n\t\tsha1 46364906A1E81DC251117E91A1A7B43AF1373ADA\n");
		printf("271-p3c.bin\tsize 1048576\n"); // 增加p3c文件的信息
	}
}

int main(int argc, char **argv)
{
	int i;

	FILE *P1_IN, *P2_IN, *P3_IN; // 增加P3_IN文件指?
	FILE *P1_OUT, *P2_OUT, *P3_OUT; // 增加P3_OUT文件指?

	// allocate ram
	unsigned char *src = (unsigned char*)malloc(0x900000); // 分配9MB?存?src

	// check input files

	if ((P1_IN=fopen("269-p1d.bin","rb"))==NULL)
	{
		print_info(0);
		fprintf(stderr,"Error: cannot read 271-p1.bin.\n");
		return(1);
	}
	fseek (P1_IN, 0, SEEK_END);
	if ((ftell (P1_IN)) != 0x900000)
	{
		print_info(0);
		fclose (P1_IN);
		return (1);
	}
	rewind (P1_IN);



// check output files
	if ((P1_OUT=fopen("269-p1.p1","wb"))==NULL)
	{
		fprintf(stderr,"Error: cannot write to 271-p1c.bin\n");
		return(1);
	}
	if ((P2_OUT=fopen("269-p2.p2","wb"))==NULL)
	{
		fprintf(stderr,"Error: cannot write to 271-p2c.bin\n");
		return(1);
	}
//	if ((P3_OUT=fopen("269-p3_no_use.p3","wb"))==NULL) // ??打?p3?出文件
//	{
//		fprintf(stderr,"Error: cannot write to 271-p3c.bin\n");
//		return(1);
//	}

	// read files
	printf("Reading input files...\n");


	for (i = 0; i < 0x900000; i+=2) // ?取P1和P2文件到src
	{
		fread(src + i + 0, 1, 2, P1_IN);

	}
	fclose(P1_IN);


	// decrypt program data
	printf("Decrypting input data...\n");


	// patch program data
	printf("Patching input data...\n");
	
	// encrypt program data
	printf ("Encrypting output data...\n");

	encryptsvc(src);	

	// write p1, p2, and p3
	printf("Writing output data...\n");
	for (i = 0; i < 0x800000; i+=4) // ?取P1和P2文件到src
	{
		fwrite(src + i + 0, 1, 2, P1_OUT);
		fwrite(src + i + 2, 1, 2, P2_OUT);
	}
//	for (i = 0x800000; i < 0x900000; i+=2) // ?入P3的加密?据
//	{
//		fwrite(src + i, 1, 2, P3_OUT);
//	}

	fclose (P1_OUT);
	fclose (P2_OUT);
//	fclose (P3_OUT);




	// deallocate ram
	free(src); // ?放src?存


	print_info(1); // 打印?出文件信息
}
