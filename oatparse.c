#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

#include "elfparse.h"
#include "dexparse.h"
#include "oatparse.h"

#if 0
typedef enum{
	true=1, 
	false=0
} bool;
#endif

const uchar kOatMagic[] = { 'o', 'a', 't', '\n' };
const uchar kOatVersion[] = { '0', '4', '6', '\0' };
const uint  kPageSize = 4096;

static void *a_buf = NULL;
static uint a_len = 0;


static Elf32_Ehdr eh;
static Elf32_Shdr *sh_tbl;
static char *sh_str;
static Elf32_Sym  *sym_tab;
static uint sym_tab_num;
static char *sym_str_tbl;
static Elf32_Sym  *dyn_sym;
static uint dyn_sym_num;
static char *dyn_str_tbl;


struct OatSec os;
struct OatHeader *oh;

uchar* file_begin = NULL, *file_end = NULL;

uchar *oatdata = NULL;
uchar *oatexec = NULL;
static uint  oatdata_offset;
static uint  oatexec_offset;

static uint getSection(int fd, void* buf, uint offset, uint size) {
	assert(lseek(fd, (off_t)offset, SEEK_SET) == (off_t)offset);
	assert(read(fd, buf, size) == size);
	return offset + size;
}

static uint getDexSection(int fd, void* buf, uint offset, uint size) {
	assert(lseek(fd, (off_t)(os.oatdata_offset+offset), SEEK_SET) == (off_t)offset);
	assert(read(fd, buf, size) == size);
	return os.oatdata_offset + offset + size;
}
bool getOatOffset() {
	uint i = 0;
	for (i = 0; i < dyn_sym_num; i++) {
		if(strcmp(dyn_str_tbl + dyn_sym[i].st_name, "oatdata") == 0) {
			os.oatdata_offset = dyn_sym[i].st_value;
			os.oatdata_size = dyn_sym[i].st_size;
		}
		if(strcmp(dyn_str_tbl + dyn_sym[i].st_name, "oatexec") == 0) {
			os.oatexec_offset = dyn_sym[i].st_value;
			os.oatexec_size = dyn_sym[i].st_size;
		}
		if(strcmp(dyn_str_tbl + dyn_sym[i].st_name, "oatlastword") == 0) {
			os.oatlastword_offset = dyn_sym[i].st_value;
			os.oatlastword_size = dyn_sym[i].st_size;
		}
	}
	return true;
}
bool OpenOat(int fd) {
	uchar *sec;
	uint i = 0;
	uint str_tbl_ndx = 0;
	read_elf_header(fd, &eh);
	if(!is_ELF(eh)) {
		return false;
	}
	sh_tbl = (Elf32_Shdr*)malloc(eh.e_shentsize * eh.e_shnum);
	if( !sh_tbl ) {
		return false;
	}
	read_section_header_table(fd, eh, sh_tbl);
	/* Read section-header string-table */
	sh_str = read_section(fd, sh_tbl[eh.e_shstrndx]);
	for (i = 0; i < eh.e_shnum; i++) {
		sec = (uchar*)sh_str+sh_tbl[i].sh_name;
		printf("[] 0x%08x 0x%08x %s\n",
				sh_tbl[i].sh_offset, 
				sh_tbl[i].sh_size,
				sec);

		if(strlen(sec) < 5)
			continue;
		if(strcmp(".rodata", sec) == 0) {
			oatdata_offset = sh_tbl[i].sh_offset;
		}
		if(strcmp(".text", sec) == 0) {
			oatexec_offset = sh_tbl[i].sh_offset;
		}
	}
	for (i = 0; i < eh.e_shnum; i++) {
		if(sh_tbl[i].sh_type == SHT_SYMTAB) {
			sym_tab = (Elf32_Sym*)read_section(fd, sh_tbl[i]);
			sym_tab_num = sh_tbl[i].sh_size/sizeof(Elf32_Sym);
			str_tbl_ndx = sh_tbl[i].sh_link;
			sym_str_tbl = read_section(fd, sh_tbl[str_tbl_ndx]);
		}
		if(sh_tbl[i].sh_type == SHT_DYNSYM) {
			dyn_sym = (Elf32_Sym*)read_section(fd, sh_tbl[i]);
			dyn_sym_num = sh_tbl[i].sh_size/sizeof(Elf32_Sym);
			str_tbl_ndx = sh_tbl[i].sh_link;
			dyn_str_tbl = read_section(fd, sh_tbl[str_tbl_ndx]);
		}
	}
	return true;
}
bool oatDexParse(uchar* oatdata, uint offset, uint count) {
	uint i = 0, j = 0;
	uint dex_file_location_size; // Length of the original input DEX path
	uint dex_file_checksum;			 // CRC32 checksum of classes.dex 
	uint dex_file_offset;				 
	uchar* dex_file_data;				 // Offset of embedded input DEX from staort of oatdata
	struct OatClassOffset* classes_offsets;      // List of offsets to OATClassHeaders
	char dex_file_location_data[255]; // Original path of input DEX file
	struct DexHeader *dh;

	uint size;
	uchar *ptr;
	/* Parse DexFile meta */
	for(i = 0; i < count; i++) {
		/* Get dex_file_location_size */
		dex_file_location_size = *(uint*)(oatdata + offset);
		offset += sizeof(uint);
		if(dex_file_location_size == 0)
			return false;
		//printf("location size: %d\n", dex_file_location_size);

		printf("\nDex file info: \n");
		/* Get dex_file_location_data */
		memcpy(dex_file_location_data, oatdata+offset, dex_file_location_size);
		offset += dex_file_location_size;
		dex_file_location_data[dex_file_location_size] = '\0';
		printf("\tFile data: %s\n", dex_file_location_data);

		/* Get dex_file_checksum */
		dex_file_checksum = *(uint*)(oatdata + offset);
		offset += sizeof(uint);
		printf("\tDex file checksum: 0x%08x\n", dex_file_checksum);

		/* Get dex_file_offset */
		dex_file_offset = *(uint*)(oatdata + offset);
		offset += sizeof(uint);
		printf("\tDex file offset: 0x%08x\n", dex_file_offset);

		classes_offsets = (struct OatClassOffset*)(oatdata + offset);

		/* Get DexFileHeader */
		dh = (struct DexHeader*)(oatdata + dex_file_offset);
		printf("\tDex file size: %d\n\n", dh->fileSize);
		oatDexFileParse(oatdata, classes_offsets, (uchar*)dh, os.oatdata_size);
		offset += (sizeof(uint) * dh->classDefsSize);
	}
	return true;
}

void printOatHeader(struct OatHeader* oheader) {
	printf("\n\nOAT header: \n");
	printf("\tadler32Checksum:\t0x%08x\n", oheader->adler32Checksum);
	printf("\tdexFileCount:\t\t%d\n", oheader->dexFileCount);
	printf("\texecutableOffset:\t0x%08x\n", oheader->executableOffset);
	printf("\tinterpreterToInterpreterBridgeOffset:\t0x%08x\n", oheader->interpreterToInterpreterBridgeOffset);
	printf("\tinterpreterToCompiledCodeBridgeOffset:\t0x%08x\n", oheader->interpreterToCompiledCodeBridgeOffset);
	printf("\tjniDlsymLookupOffset:\t\t\t0x%08x\n", oheader->jniDlsymLookupOffset);
	printf("\tquickGenericJniTrampolineOffset:\t0x%08x\n", oheader->quickGenericJniTrampolineOffset);
	printf("\tquickImtConflictTrampolineOffset:\t0x%08x\n", oheader->quickImtConflictTrampolineOffset);
	printf("\tquickResolutionTrampolineOffset:\t0x%08x\n", oheader->quickResolutionTrampolineOffset);
	printf("\tquickToInterpreterBridgeOffset:\t\t0x%08x\n", oheader->quickToInterpreterBridgeOffset);
	printf("\timageFileLocationOatDataBegin:\t\t0x%08x\n", oheader->imageFileLocationOatDataBegin);
	printf("\n");
}

int main(int argc, char *argv[]) 
{
	bool res;
	uint i = 0;
	uint offset = 0;
	uint fileLength;
	uchar tmp[1];
	if ( argc < 2)
		return 0;
	int fd = open(argv[1], O_RDWR|O_SYNC, S_IRUSR|S_IWUSR); 
	if (fd < 0)
		return 0;
	/* A dictonary containing information such as the command line used 
	 * to generate this oat file, the host artch, etc.
	 */
	uchar *key_value_store;
	res = OpenOat(fd);
	getOatOffset();
	printf("\noatdata:\t\t0x%08x  0x%08x\n", os.oatdata_offset, os.oatdata_size);
	printf("oatexec:\t\t0x%08x  0x%08x\n", os.oatexec_offset, os.oatexec_size);
	printf("oatlastword:\t0x%08x  0x%08x\n\n", os.oatlastword_offset, os.oatlastword_size);
	
	fileLength = os.oatlastword_offset+os.oatlastword_size;
	
	lseek(fd, fileLength, SEEK_SET);
	read(fd,tmp,1);
	
	file_begin = mmap(0, os.oatlastword_offset+os.oatlastword_size, 
			PROT_READ, MAP_PRIVATE, fd, 0);
	if( file_begin == MAP_FAILED ) {
		fprintf(stderr, "mmap error.\n");
		exit(1);
	}
	file_end = file_begin+os.oatlastword_offset+os.oatlastword_size;
	if( close(fd) == -1 ) {
		fprintf(stderr, "Close error.\n");
		exit(1);
	}
	oatdata = file_begin + oatdata_offset;
	oatexec = file_begin + oatexec_offset;
	offset = 0;
	oh = (struct OatHeader*)oatdata;
	offset += sizeof(struct OatHeader);
	if(memcmp(oh->magic, "oat\n", 4) != 0) {
		printf("%s\n", oh->magic);
		return false;
	}
	key_value_store = oatdata + offset;
	offset += oh->keyValueStoreSize;
	for(i=0;i<oh->keyValueStoreSize;i++) printf("%c", key_value_store[i]);
	//ffset += oh->keyValueStoreSize;
	printOatHeader(oh);
	//printf("\ndex file count: %d\n", oh->dexFileCount);
	oatDexParse(oatdata, offset, oh->dexFileCount);

	if(munmap(file_begin, os.oatlastword_offset+os.oatlastword_size) == -1) {
		fprintf(stderr, "munmap error.\n");
		exit(1);
	}
	free(sh_tbl);
	free(sh_str);
	free(sym_str_tbl);
	free(dyn_str_tbl);
	free(sym_tab);
	free(dyn_sym);
	return 0;
}
