/*---------------------------------------------------------------------*\
|	This source is by IQ_132 -- http://neosource.1emulation.com/	|
|	You may use this code in any way you wish. 			|
\*---------------------------------------------------------------------*/

#include <stdio.h>

// BITSWAP8 function from FBA
#define BITSWAP8(n, 						\
	bit07, bit06, bit05, bit04, bit03, bit02, bit01, bit00)	\
	(((((n) >> (bit07)) & 1) <<  7) | 			\
	 ((((n) >> (bit06)) & 1) <<  6) | 			\
	 ((((n) >> (bit05)) & 1) <<  5) | 			\
	 ((((n) >> (bit04)) & 1) <<  4) | 			\
	 ((((n) >> (bit03)) & 1) <<  3) | 			\
	 ((((n) >> (bit02)) & 1) <<  2) | 			\
	 ((((n) >> (bit01)) & 1) <<  1) | 			\
	 ((((n) >> (bit00)) & 1) <<  0))

void modify_prgdata(unsigned char *dst)
{
	*((unsigned short*)(dst + 0x122A)) = 0x6700; // Remove AES Fix
	*((unsigned short*)(dst + 0x122C)) = 0x0034;

	// Check to see if P is in the incorrect order
	if (dst[0x300007] != 0x57)
	{
		if (dst[0x400007] == 0x57) // Check for P saved from RAM of an Emulator
		{
			printf ("This appears to be saved from RAM. Fixing this...\n");
			memcpy(dst + 0x100000, dst + 0x200000, 0x600000);
		}
		else if (dst[0x200007] == 0x57) // Check for "bootleg" P
		{
			printf ("This appears to be a \"Bootleg\" ROM. Fixing this...\n");
			memcpy(dst + 0x700000, dst + 0x200000, 0x100000);
			memcpy(dst + 0x200000, dst + 0x300000, 0x100000);
			memcpy(dst + 0x300000, dst + 0x700000, 0x100000);
		}
	}

	int i;
	for (i = 0x500000; i < 0x800000; i++) dst[i] = 0xFF;
}

int main(int argc, char **argv)
{
	int i, ofst, size;
	unsigned char *src = (unsigned char*)malloc(0x800000); 
	unsigned char *dst = (unsigned char*)malloc(0x800000);

	FILE *PIN;

	if ((PIN=fopen("268-p1d.bin","rb"))==NULL)
	{
		fprintf(stderr,"Error: cannot read 268-p1d.bin.");
		return(1);
	}

	fseek (PIN , 0 , SEEK_END);
	size = ftell (PIN); rewind (PIN);

	if (size < 0x500000)
	{
		fprintf(stderr, "Error: This file must be at least 5242880 bytes (5MB).");
		fclose (PIN); return(1);
	}

	fread (dst, 1, size, PIN);  fclose (PIN);

	modify_prgdata(dst);

// -----------------------------------------------------------------------------------------------

	// Based on code by Halrin

	unsigned int xor1[ 0x20 ] = {
		0xc2, 0x4b, 0x74, 0xfd, 0x0b, 0x34, 0xeb, 0xd7, 0x10, 0x6d, 0xf9, 0xce, 0x5d, 0xd5, 0x61, 0x29,
		0xf5, 0xbe, 0x0d, 0x82, 0x72, 0x45, 0x0f, 0x24, 0xb3, 0x34, 0x1b, 0x99, 0xea, 0x09, 0xf3, 0x03
	};

	unsigned int xor2[ 0x20 ] = {
		0x36, 0x09, 0xb0, 0x64, 0x95, 0x0f, 0x90, 0x42, 0x6e, 0x0f, 0x30, 0xf6, 0xe5, 0x08, 0x30, 0x64,
		0x08, 0x04, 0x00, 0x2f, 0x72, 0x09, 0xa0, 0x13, 0xc9, 0x0b, 0xa0, 0x3e, 0xc2, 0x00, 0x40, 0x2b
	};

	for( i = 0; i < 0x10; i++ ){
		ofst = (i & 0xf0) + BITSWAP8( (i & 0x0f), 7, 6, 5, 4, 1, 0, 3, 2 );
		memcpy( src + (i * 0x10000), dst + (ofst * 0x10000), 0x10000 );
	}

	for( i = 0; i < 0x100000; i++ )
		src[ i ] ^= xor1[ (i % 0x20) ];

	for( i = 0x100000; i < 0x800000; i += 0x100 ){
		ofst = (i & 0xf000ff) + ((i & 0x000f00) ^ 0x00700) +
			(BITSWAP8( ((i & 0x0ff000) >> 12), 5, 4, 7, 6, 1, 0, 3, 2 ) << 12);
		memcpy( src + ofst, dst + i, 0x100 );
	}

	for( i = 0x100000; i < 0x800000; i += 4 ){
		unsigned short *rom16 = (unsigned short*)&src[ i + 1 ];
		*rom16 = (BITSWAP8((*rom16&0xFF0)>>4, 6,7,4,5,2,3,0,1)<<4)|(*rom16&0xF00F);
	}

	for( i = 0x100000; i < 0x800000; i++ )
		src[ i ] ^= xor2[ (i % 0x20) ];

// -----------------------------------------------------------------------------------------------

	FILE *POUTA = fopen ("268-p1cr.bin", "wb");
	FILE *POUTB = fopen ("268-p2cr.bin", "wb");

	for (i = 0; i < 0x800000; i+=4)
	{
		fwrite (src + i + 0, 1, 2, POUTA);
		fwrite (src + i + 2, 1, 2, POUTB);
	}

	fclose (POUTA);
	fclose (POUTB);

	free(dst);
	free(src);

	printf ("Finished!\n");
}
