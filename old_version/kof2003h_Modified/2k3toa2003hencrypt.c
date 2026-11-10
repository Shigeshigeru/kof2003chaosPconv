
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
		 
static void decrypt2003(unsigned char *src)

{
//	 const unsigned char xor1[0x20] = { 0x3B, 0x6A, 0xF7, 0xB7, 0xE8, 0xA9, 0x20, 0x99, 0x9F, 0x39, 0x34, 0x0C, 0xC3, 0x9A, 0xA5, 0xC8, 0xB8, 0x18, 0xCE, 0x56, 0x94, 0x44, 0xE3, 0x7A, 0xF7, 0xDD, 0x42, 0xF0, 0x18, 0x60, 0x92, 0x9F };
//	 const unsigned char xor2[0x20] = { 0x2F, 0x02, 0x60, 0xBB, 0x77, 0x01, 0x30, 0x08, 0xD8, 0x01, 0xA0, 0xDF, 0x37, 0x0A, 0xF0, 0x65, 0x28, 0x03, 0xD0, 0x23, 0xD3, 0x03, 0x70, 0x42, 0xBB, 0x06, 0xF0, 0x28, 0xBA, 0x0F, 0xF0, 0x7A };

	 const unsigned char xor1[0x20] = { 0xc2, 0x4b, 0x74, 0xfd, 0x0b, 0x34, 0xeb, 0xd7, 0x10, 0x6d, 0xf9, 0xce, 0x5d, 0xd5, 0x61, 0x29, 0xf5, 0xbe, 0x0d, 0x82, 0x72, 0x45, 0x0f, 0x24, 0xb3, 0x34, 0x1b, 0x99, 0xea, 0x09, 0xf3, 0x03 };
	 const unsigned char xor2[0x20] = { 0x2b, 0x09, 0xd0, 0x7f, 0x51, 0x0b, 0x10, 0x4c, 0x5b, 0x07, 0x70, 0x9d, 0x3e, 0x0b, 0xb0, 0xb6, 0x54, 0x09, 0xe0, 0xcc, 0x3d, 0x0d, 0x80, 0x99, 0x87, 0x03, 0x90, 0x82, 0xfe, 0x04, 0x20, 0x18 };


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
//		*rom16 = BITSWAP16( *rom16, 15, 14, 13, 12, 5, 4, 7, 6, 9, 8, 11, 10, 3, 2, 1, 0 );	}
		*rom16 = BITSWAP16( *rom16, 15, 14, 13, 12, 10, 11, 8, 9, 6, 7, 4, 5, 3, 2, 1, 0 );	}

	memcpy(dst, src, 0x800000);


	for (i = 0; i < 0x10; i++) {
//		ofst = (i & 0xf0) + BITSWAP8((i & 0x0f), 7, 6, 5, 4, 0, 1, 2, 3);
		ofst = (i & 0xf0) + BITSWAP8((i & 0x0f), 7, 6, 5, 4, 1, 0, 3, 2);
		memcpy(&dst[i * 0x10000], &src[ofst * 0x10000], 0x10000);
	}

	for (i = 0x100000; i < 0x900000; i += 0x100) {
//		ofst = (i & 0xf000ff) + ((i & 0x000f00) ^ 0x00800)
		ofst = (i & 0xf000ff) + ((i & 0x000f00) ^ 0x00400)
//			+ (BITSWAP8(((i & 0x0ff000) >> 12), 4, 5, 6, 7, 1, 0, 3, 2 ) << 12);
			+ (BITSWAP8(((i & 0x0ff000) >> 12), 6, 7, 4, 5, 0, 1, 2, 3 ) << 12);
		memcpy(&dst[i], &src[ofst], 0x100);
	}
	memcpy (&src[0x000000], &dst[0x000000], 0x100000);
	memcpy (&src[0x100000], &dst[0x800000], 0x100000);
	memcpy (&src[0x200000], &dst[0x100000], 0x700000);
	free(dst);
}

static void encrypt2003(unsigned char *src)

{
	int i, ofst;

	unsigned char xor1[0x20] = {
//		0x3B, 0x6A, 0xF7, 0xB7, 0xE8, 0xA9, 0x20, 0x99, 0x9F, 0x39, 0x34, 0x0C, 0xC3, 0x9A, 0xA5, 0xC8,
//		0xB8, 0x18, 0xCE, 0x56, 0x94, 0x44, 0xE3, 0x7A, 0xF7, 0xDD, 0x42, 0xF0, 0x18, 0x60, 0x92, 0x9F,
		0xc2, 0x4b, 0x74, 0xfd, 0x0b, 0x34, 0xeb, 0xd7, 0x10, 0x6d, 0xf9, 0xce, 0x5d, 0xd5, 0x61, 0x29,
		0xf5, 0xbe, 0x0d, 0x82, 0x72, 0x45, 0x0f, 0x24, 0xb3, 0x34, 0x1b, 0x99, 0xea, 0x09, 0xf3, 0x03,
	};

	unsigned char xor2[0x20] = {
//		0x2F, 0x02, 0x60, 0xBB, 0x77, 0x01, 0x30, 0x08, 0xD8, 0x01, 0xA0, 0xDF, 0x37, 0x0A, 0xF0, 0x65,
//		0x28, 0x03, 0xD0, 0x23, 0xD3, 0x03, 0x70, 0x42, 0xBB, 0x06, 0xF0, 0x28, 0xBA, 0x0F, 0xF0, 0x7A
		0x2b, 0x09, 0xd0, 0x7f, 0x51, 0x0b, 0x10, 0x4c, 0x5b, 0x07, 0x70, 0x9d, 0x3e, 0x0b, 0xb0, 0xb6,
		0x54, 0x09, 0xe0, 0xcc, 0x3d, 0x0d, 0x80, 0x99, 0x87, 0x03, 0x90, 0x82, 0xfe, 0x04, 0x20, 0x18
	};

	unsigned char *dst = (unsigned char*)malloc(0x900000);

	// copy everything to dst
        memcpy (&dst[0x000000], &src[0x000000], 0x100000);
        memcpy (&dst[0x800000], &src[0x100000], 0x100000);
        memcpy (&dst[0x100000], &src[0x200000], 0x700000);
        
       for( i = 0x100000; i < 0x900000; i += 0x100)
        {
//            ofst = (i & 0xf000ff) + ((i & 0x000f00) ^ 0x00800) + (BITSWAP8( ((i & 0x0ff000) >> 12), 4, 5, 6, 7, 1, 0, 3, 2 ) << 12);
              ofst = (i & 0xf000ff) + ((i & 0x000f00) ^ 0x00400) + (BITSWAP8( ((i & 0x0ff000) >> 12), 6, 7, 4, 5, 0, 1, 2, 3 ) << 12);
                memcpy( &src[ i ], &dst[ ofst ], 0x100 );
        }

        for( i = 0; i < 0x0100000 / 0x10000; i++ )
        {
//              ofst = (i & 0xf0) + BITSWAP8((i & 0x0f), 7, 6, 5, 4, 0, 1, 2, 3 );
                ofst = (i & 0xf0) + BITSWAP8((i & 0x0f), 7, 6, 5, 4, 1, 0, 3, 2 );
                memcpy( &src[ i * 0x10000 ], &dst[ ofst * 0x10000 ], 0x10000 );
        }

        for( i = 0x100000; i < 0x800000; i += 4)
        {
		unsigned short *rom16 = (unsigned short*)&src[ i + 1 ];
//		*rom16 = (BITSWAP8((*rom16&0xFF0)>>4, 1,0,3,2,5,4,7,6)<<4)|(*rom16&0xF00F);
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

//		0x59, 0xF8, 0x39, 0x0C, 0x03, 0x00, 0xc0, 0x00, 0x01, 0x04, 0x00, 0x66, 0x08, 0x00, 0x7c, 0x1b, 
//		0x59, 0xF8

//	};

//	*((unsigned short*)(src + 0x00C0)) = 0x4638;
//	*((unsigned short*)(src + 0x00C0)) = 0x77C0;
//	*((unsigned short*)(src + 0x00C2)) = 0x5F50;
//	*((unsigned short*)(src + 0x00C2)) = 0x89E7;
//	*((unsigned short*)(src + 0x0408)) = 0x4465;
//	*((unsigned short*)(src + 0x0408)) = 0x4E6F;
//	*((unsigned short*)(src + 0x040A)) = 0x6320;
//	*((unsigned short*)(src + 0x040A)) = 0x7620;
//	*((unsigned short*)(src + 0x040C)) = 0x3031;
//	*((unsigned short*)(src + 0x040C)) = 0x3234;
//	*((unsigned short*)(src + 0x0412)) = 0x3133;
//	*((unsigned short*)(src + 0x0412)) = 0x3032;
//	*((unsigned short*)(src + 0x0414)) = 0x3A34;
//	*((unsigned short*)(src + 0x0414)) = 0x3A35;
//	*((unsigned short*)(src + 0x0416)) = 0x3820;
//	*((unsigned short*)(src + 0x0416)) = 0x3520;
//}
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

	if ((P1_IN=fopen("p1.bin","rb"))==NULL)
	{
		print_info(0);
		fprintf(stderr,"Error: cannot read p1.bin.\n");
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
	if ((P1_OUT=fopen("271-p1k.p1","wb"))==NULL)
	{
		fprintf(stderr,"Error: cannot write to 271-p1k.p1\n");
		return(1);
	}
	if ((P2_OUT=fopen("271-p2k.p2","wb"))==NULL)
	{
		fprintf(stderr,"Error: cannot write to 271-p2k.p2\n");
		return(1);
	}
	if ((P3_OUT=fopen("271-p3k.p3","wb"))==NULL) // ??打?p3?出文件
	{
		fprintf(stderr,"Error: cannot write to 271-p3k.p3\n");
		return(1);
	}

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

	encrypt2003(src);	

	// write p1, p2, and p3
	printf("Writing output data...\n");
	for (i = 0; i < 0x800000; i+=4) // ?取P1和P2文件到src
	{
		fwrite(src + i + 0, 1, 2, P1_OUT);
		fwrite(src + i + 2, 1, 2, P2_OUT);
	}
	for (i = 0x800000; i < 0x900000; i+=2) // ?入P3的加密?据
	{
		fwrite(src + i, 1, 2, P3_OUT);
	}

	fclose (P1_OUT);
	fclose (P2_OUT);
	fclose (P3_OUT);




	// deallocate ram
	free(src); // ?放src?存


	print_info(1); // 打印?出文件信息
}
