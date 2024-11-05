#include <stdio.h>

void usage()
{
	printf("USAGE:\n");
	printf("\ts1grab.exe c7_file c8_file\n");
}

int main(int argc, char **argv)
{
	FILE *c1_rom_in, *c2_rom_in, *s1_rom_out;
	int s_size = 0x80000;
	char name[0];
	int i;
	int ROMSize = 0;
	int ROMSizeb = 0;

	if (argc != 3)
	{
		usage();
		return(1);
	}

	// Scan arguments for file name
	sscanf(argv[1],"%s",&name);

	printf("Checking input\n");
	// Check input files
	if ((c1_rom_in=fopen(name,"rb"))==NULL)
	{
		fprintf(stderr,"Error: cannot read %s.",name);
		return(1);
	}
	fseek (c1_rom_in , 0 , SEEK_END);
	ROMSize += ftell (c1_rom_in);
	rewind (c1_rom_in);

	// Scan arguments for file name
	sscanf(argv[2],"%s",&name);

	// Check input files
	if ((c2_rom_in=fopen(name,"rb"))==NULL)
	{
		fprintf(stderr,"Error: cannot read %s.",name);
		return(1);
	}
	fseek (c2_rom_in , 0 , SEEK_END);
	ROMSizeb += ftell (c2_rom_in);
	rewind (c2_rom_in);

	if (ROMSize != ROMSizeb)
	{
		printf("Input sizes must match!");
		return(1);
	}

	printf("Checking output\n");
	// Check output files
	if ((s1_rom_out=fopen("s1_out.bin","wb"))==NULL)
	{
		fclose(s1_rom_out);
		fprintf(stderr,"Error: cannot write to s1_out.bin.");
		return(1);
	}

	printf("Allocate RAM\n");
	// Create buffer
	unsigned char *src = (unsigned char*)malloc(s_size);

	fseek (c1_rom_in,(ROMSize-(s_size/2)),SEEK_SET);
	fseek (c2_rom_in,(ROMSize-(s_size/2)),SEEK_SET);

	printf("Read, process, and close input file\n");
	for (i = 0; i < s_size; i+=2)
	{
		fread (src+i+0,1,1,c1_rom_in);
		fread (src+i+1,1,1,c2_rom_in);
	}
	fclose(c1_rom_in);
	fclose(c2_rom_in);

	unsigned char *dst = (unsigned char*)malloc(s_size);
	for (i = 0;i < s_size;i++)
		dst[i] = src[(i & ~0x1f) + ((i & 7) << 2) + ((~i & 8) >> 2) + ((i & 0x10) >> 4)];
	memcpy(src, dst, s_size);

	printf("Write output\n");
	// Write the output
	fwrite (src,1,s_size,s1_rom_out);
	fclose(s1_rom_out);

	printf("Free Allocated RAM\n");
	// Free buffer
	free(src);
	free(dst);

	printf("Finished\n");
}
