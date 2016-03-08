// dexparse.c
/*--- Parse DEX files ---*/

#include "elfparse.h"
#include "oatparse.h"
#include "dexparse.h"

/*names for the access flags*/
const char * ACCESS_FLAG_NAMES[20] = {
	"public",       
	"private",
	"protected",
	"static",       
	"final",      
	"synchronized",
	"super",  
	"volatile",
	"bridge",   
	"transient",
	"varargs",
	"native",
	"interface",
	"abstract",
	"strict",
	"synthetic",
	"annotation",
	"enum",    
	"constructor",
	"declared_synchronized"};

const uint ACCESS_FLAG_VALUES[20] = {
	0x00000001,
	0x00000002,
	0x00000004,
	0x00000008,
	0x00000010,
	0x00000020,
	0x00000020,
	0x00000040,
	0x00000040,
	0x00000080,
	0x00000080,
	0x00000100,
	0x00000200,
	0x00000400,
	0x00000800,
	0x00001000,
	0x00002000,
	0x00004000,
	0x00010000,
	0x00020000};

const char * OAT_CLASS_TYPE[3] = {
	"kOatClassAllCompiled",
	"kOatClassSomeCompiled",
	"kOatClassNoneCompiled"
};

extern uchar* file_begin;
extern uchar* file_end;

int readUnsignedLeb128(uchar** pStream)
{
	/* taken from dalvik's libdex/Leb128.h */
	uchar* ptr = *pStream;
	int result = *(ptr++);

	if (result > 0x7f) {
		int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					/*
					 * Note: We don't check to see if cur is out of
					 * range here, meaning we tolerate garbage in the
					 * high four-order bits.
					 * */
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}

	*pStream = ptr;
	return result;
}

uint uleb128_value(uchar* pStream)
{
	uchar* ptr = pStream;
	int result = *(ptr++);

	if (result > 0x7f) {
		int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					/*
					 * Note: We don't check to see if cur is out of
					 * range here, meaning we tolerate garbage in the
					 * high four-order bits.
					 */
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}


uint len_uleb128(unsigned long n)
{
	static uchar b[32];
	uint i;

	i = 0;
	do
	{
		b[i] = n & 0x7F;
		if (n >>= 7)
			b[i] |= 0x80;
	}
	while (b[i++] & 0x80);
	return i;
}

void getUnsignedLebValue(uchar* dex, uchar* stringData,
		uint offset) {
	uchar* uLebBuff;
	uint uLebValue, uLebValueLength;
	uLebBuff = dex + offset;

	uLebValue = uleb128_value(uLebBuff);
	uLebValueLength = len_uleb128(uLebValue);

	memcpy(stringData, dex+offset+uLebValueLength, uLebValue);
	stringData[uLebValue] = '\0';
}

uint getTypeDescForClass(uchar* dex, struct StringID* strIdList,
		struct TypeID* typeIdList, struct ClassDefine* classDefItem,
		uchar* stringData) {
	uint strIdOff = 0;
	if(classDefItem->classId) {
		strIdOff = strIdList[typeIdList[classDefItem->classId].descriptorId].stringDataOff;
		getUnsignedLebValue(dex, stringData, strIdOff);
	} else {
		strcpy(stringData, "Unknown");
	}
	return strIdOff;
}

void getTypeDesc(uchar* dex, struct StringID *strIdList,
		struct TypeID* typeIdList, uint offset_pointer,
		uchar* stringData){
	uint strIdOff;
	if (offset_pointer){
		strIdOff = strIdList[typeIdList[offset_pointer].descriptorId].stringDataOff; /*get the offset to the string in the data section*/
		/*would be cool if we have a RAW mode, with only hex unparsed data, and a SYMBOLIC mode where all the data is parsed and interpreted */
		getUnsignedLebValue(dex,stringData,strIdOff);
	}
	else{
		strcpy(stringData, "Unknown");
	}
}

void getProtoDesc(uchar* dex, struct StringID *strIdList,
		struct TypeID* typeIdList,
		struct ProtoID* protoIdList, uint offset_pointer,
		uchar* returnType, uchar* shorty, uchar* params){
	uint strIdOff, p, *tmp;
	if (offset_pointer){
		strIdOff = strIdList[typeIdList[protoIdList[offset_pointer].returnTypeId].descriptorId].stringDataOff; 
		getUnsignedLebValue(dex, returnType, strIdOff);
		strIdOff = strIdList[protoIdList[offset_pointer].shortyId].stringDataOff;
		getUnsignedLebValue(dex, shorty, strIdOff);
		if( protoIdList[offset_pointer].parametersOff == 0)
			p = 0;
		else {
			tmp = (uint*)&dex[protoIdList[offset_pointer].parametersOff];
			p = *tmp;
		}
		strIdOff = strIdList[typeIdList[p].descriptorId].stringDataOff;
		getUnsignedLebValue(dex, params, strIdOff);
	}
	else{
		strcpy(returnType, "Unknown");
		strcpy(shorty, "Unknown");
		strcpy(params, "Unknown");
	}
}

void getClassFileName(uchar* dex, struct StringID *strIdList, 
		struct ClassDefine *classDefItem, uchar *stringData) {
	uint strIdOff;
	//printf("Source file ID: %d\n", classDefItem->sourceFileId);
	if(classDefItem->sourceFileId) {
		strIdOff = strIdList[classDefItem->sourceFileId].stringDataOff;
		//printf("String offset: 0x%x\n", strIdOff);
		getUnsignedLebValue(dex, stringData, strIdOff);
	} else {
		stringData[0] = '\0';
	}
}
/*this allows us to print ACC_FLAGS symbolically*/
uchar* parseAccessFlags(uint flags){
	int i = 0;
	if (flags){
		for (;i<20;i++){
			if (flags & ACCESS_FLAG_VALUES[i]){
				//printf(" %s ",ACCESS_FLAG_NAMES[i]);
				return ACCESS_FLAG_NAMES[i];
			}
		}	
	}
	return NULL;
}

/*not entirely sure how I should use these methods, as is they are only usefull for printing values, and don't return them :/
 * though as a tradeoff I've made the methods manipulate the string data in place, so the conversion to returning them would be easy */
/*Generic methods for printing types*/
void getStringValue(uchar* dex, struct StringID *strIdList,
		uint offset_pointer,uchar* stringData){

	uint strIdOff;
	if (offset_pointer){
		strIdOff = strIdList[offset_pointer].stringDataOff; /*get the offset to the string in the data section*/
		/*would be cool if we have a RAW mode, with only hex unparsed data, and a SYMBOLIC mode where all the data is parsed and interpreted */
		getUnsignedLebValue(dex,stringData,strIdOff);
	}
	else{
		strcpy(stringData, "Unknown");
	}
}

bool dump(uchar* buf, uint size) {
	assert(buf != NULL);
	int fout = open("./dump.dex", O_WRONLY | O_CREAT | O_SYNC);
	write(fout, buf, size);
	close(fout);
	return true;
}
#if 0
bool dexClassParse(uchar*dexBuf, uint offset, 
		struct StringID *string_id_list,
		struct TypeID *type_id_list,
		struct MethodID *method_id_list) {

	struct ClassDefine *class_def_item;

	uchar str[255], *buffer, *buf, *ptr;

	int len = 0;
	int field_idx_diff;
	int field_access_flags;

	int method_idx_diff;
	int method_access_flags;
	int method_code_off;

	int key = 0, i = 0;

	uint  static_fields_size; 
	uint  instance_fields_size;
	uint  direct_methods_size;
	uint  virtual_methods_size;

	int size_uleb, size_uleb_value;

	struct DexHeader *dh = (struct DexHeader*)dexBuf;

	//printf("[] classDefOff: 0x%x\n", offset);
	class_def_item = (struct ClassDefine*)(dexBuf + offset);
	if(class_def_item->sourceFileId != NO_INDEX ){
		getClassFileName(dexBuf, string_id_list, class_def_item, str);
		printf("( %s )\n", str);
	} else {
		printf("(No index): ");
	}

	/* print debug info */
	printf("\tclass_idx='0x%x':", class_def_item->classId);
	getTypeDescForClass(dexBuf, string_id_list,type_id_list,class_def_item,str);
	printf("( %s )\n", str);
	printf("\taccess_flags='0x%x'\n", class_def_item->accessFlags); /*need to interpret this*/
	parseAccessFlags(class_def_item->accessFlags);
	printf("\tsuperclass_idx='0x%x':", class_def_item->superClassId);
	getTypeDesc(dexBuf, string_id_list, type_id_list, class_def_item->superClassId,str);
	printf("( %s )\n", str);
	printf("\tinterfaces_off='0x%x'\n", class_def_item->interfaceOff); /*need to look this up in the DexTypeList*/
	printf("\tsource_file_idx='0x%x'\n", class_def_item->sourceFileId);
#if 0
	if (class_def_item->sourceFileId != NO_INDEX)
	{
		getStringValue(dexBuf, string_id_list, class_def_item->sourceFileId, str); //causes a seg fault on some dex files
		printf("( %s )\n", str);
	}
#endif
	printf("\tannotations_off=0x%x\n", class_def_item->annotationsOff);
	printf("\tclass_data_off=0x%x (%d)\n", class_def_item->classDataOff, class_def_item->classDataOff);
	printf("\tstatic_values_off=0x%x (%d)\n", class_def_item->staticValuesOff, class_def_item->staticValuesOff);

	/* change position to classDataOff */
	if (class_def_item->classDataOff == 0) {
		if (DEBUG) {
			printf ("\t0 static fields\n");
			printf ("\t0 instance fields\n");
			printf ("\t0 direct methods\n");
		} else {
			printf ("0 direct methods, 0 virtual methods\n");
		}
		return false;
	} else {
		offset = class_def_item->classDataOff;
	}
	len = dh->mapOff - offset;
	if(len < 1) {
		len = dh->fileSize - offset;
		if(len < 1) {
			fprintf(stderr, "ERROR: invalid file length in dex header \n");
			exit(1);
		}
	}
	buffer = malloc(len);
	assert(buffer != NULL);
	memcpy(buffer, dexBuf+offset, len);
	ptr = buffer;
	static_fields_size = readUnsignedLeb128(&buffer);
	instance_fields_size = readUnsignedLeb128(&buffer);
	direct_methods_size = readUnsignedLeb128(&buffer);
	virtual_methods_size = readUnsignedLeb128(&buffer);

	if(DEBUG) printf("\t%d static fields\n", static_fields_size);

	for(i = 0; i < static_fields_size; i++) {
		field_idx_diff = readUnsignedLeb128(&buffer);
		field_access_flags = readUnsignedLeb128(&buffer);
		if(DEBUG) {
			printf ("\t\t[%d]|--field_idx_diff='0x%x'\n", i,field_idx_diff);
			//printTypeDesc(string_id_list,type_id_list,field_idx_diff,input,str,"%s\n");
			printf ("\t\t    |--field_access_flags='0x%x' :",field_access_flags);
			parseAccessFlags(field_access_flags);
		}
	}
	if (DEBUG) printf ("\t%d instance fields\n", instance_fields_size);
	for (i=0;i<instance_fields_size;i++) {
		field_idx_diff = readUnsignedLeb128(&buffer);
		field_access_flags = readUnsignedLeb128(&buffer);
		if (DEBUG) {
			printf ("\t\t[%d]|--field_idx_diff='0x%x'\n", i,field_idx_diff);
			printf ("\t\t    |--field_access_flags='0x%x' :",field_access_flags);
			parseAccessFlags(field_access_flags);
		}
	}

	if (!DEBUG) printf ("%d direct methods, %d virtual methods\n", direct_methods_size, virtual_methods_size);
	if (DEBUG) printf ("\t%d direct methods\n", direct_methods_size);

	key=0;
	for (i=0;i<direct_methods_size;i++) {
		method_idx_diff = readUnsignedLeb128(&buffer);
		method_access_flags = readUnsignedLeb128(&buffer);
		method_code_off = readUnsignedLeb128(&buffer);

		/* methods */
		if (key == 0) key=method_idx_diff;
		else key += method_idx_diff;

		ushort class_idx = method_id_list[key].classId;
		ushort proto_idx = method_id_list[key].protoId;
		uint   name_idx  = method_id_list[key].nameId;

		/* print method name ... should really do this stuff through a common function, its going to be annoying to debug this...:/ */
		offset = string_id_list[name_idx].stringDataOff;
		buf = malloc(10);
		assert(buf != NULL);
		memcpy(buf, dexBuf+offset, 10);

		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);

		memcpy(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';

		printf ("\tdirect method %d = %s\n",i+1, str);
		if (DEBUG) {
			printf("\t\tmethod_code_off=0x%x\n", method_code_off);
			printf("\t\tmethod_access_flags='0x%x'\n", method_access_flags);
			//parseAccessFlags(method_access_flags);	
			printf("\t\tclass_idx='0x%x'\n", class_idx);
			//printTypeDesc(string_id_list,type_id_list,class_idx,input,str," %s\n");
			printf("\t\tproto_idx=0x%x\n", proto_idx);
		}
		free(buf);
	}
	if (DEBUG) printf ("\t%d virtual methods\n", virtual_methods_size);

	key=0;
	for (i=0;i<virtual_methods_size;i++) {
		method_idx_diff = readUnsignedLeb128(&buffer);
		method_access_flags = readUnsignedLeb128(&buffer);
		method_code_off = readUnsignedLeb128(&buffer);

		/* methods */
		if (key == 0) key=method_idx_diff;
		else key += method_idx_diff;

		ushort class_idx = method_id_list[key].classId;
		ushort proto_idx = method_id_list[key].protoId;
		uint    name_idx  = method_id_list[key].nameId;

		/* print method name */
		offset=string_id_list[name_idx].stringDataOff;
		//printStringValue(string_id_list,name_idx,input,str,"%s\n");
		buf = malloc(10);
		assert(buf != NULL);
		memcpy(buf, dexBuf+offset, 10);
		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		// offset2: on esta el tamany (size_uleb_value) en uleb32 de la string, seguit de la string 
		memcpy(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';
		printf ("\tvirtual method %d = %s (method_id_idx=%d)\n",i+1, str, key);

		if (DEBUG) {
			printf("\t\tmethod_code_off=0x%x\n", method_code_off);
			printf("\t\tmethod_access_flags='0x%x'\n", method_access_flags);
			//parseAccessFlags(method_access_flags);	
			printf("\t\tclass_idx=0x%x\n", class_idx);
			printf("\t\tproto_idx=0x%x\n", proto_idx);
		}

	}
	free(ptr);
	return true;
}
bool dexFileParse(uchar* dexBuf, uint size) {
	uint j = 0;
	struct DexHeader *dh;

	struct MethodID *method_id_list;
	struct StringID *string_id_list;
	struct TypeID   *type_id_list;

	uint  offset = 0;

	dh = (struct DexHeader*)dexBuf;
	//dump(fd, dexOffset+dex_file_offset, dh.fileSize);
	if (1) {
		printf("[] DEX magic: ");
		for(j=0;j<8;j++) printf("%02x ", dh->magic[j]);
		printf("\n");
		printf("[] DEX version: %s\n", &dh->magic[4]);
		printf("[] Adler32 checksum: 0x%x\n", dh->checksum);
		printf("[] Dex file size: %d\n", dh->fileSize);
		printf("[] Dex header size: %d bytes (0x%x)\n", dh->headerSize, dh->headerSize);
		printf("[] Endian Tag: 0x%x\n", dh->endianTag);
		printf("[] Link size: %d\n", dh->linkSize);
		printf("[] Link offset: 0x%x\n", dh->linkOff);
		printf("[] Map list offset: 0x%x\n", dh->mapOff);
		printf("[] Number of strings in string ID list: %d\n", dh->stringIdsSize);
		printf("[] String ID list offset: 0x%x\n", dh->stringIdsOff);
		printf("[] Number of types in the type ID list: %d\n", dh->typeIdsSize);
		printf("[] Type ID list offset: 0x%x\n", dh->typeIdsOff);
		printf("[] Number of items in the method prototype ID list: %d\n", dh->protoIdsSize);
		printf("[] Method prototype ID list offset: 0x%x\n", dh->protoIdsOff);
		printf("[] Number of item in the field ID list: %d\n", dh->fieldIdsSize);
		printf("[] Field ID list offset: 0x%x\n", dh->fieldIdsOff);
		printf("[] Number of items in the method ID list: %d\n", dh->methodIdsSize);
		printf("[] Method ID list offset: 0x%x\n", dh->methodIdsOff);
		printf("[] Number of items in the class definitions list: %d\n", dh->classDefsSize);
		printf("[] Class definitions list offset: 0x%x\n", dh->classDefsOff);
		printf("[] Data section size: %d bytes\n", dh->dataSize);
		printf("[] Data section offset: 0x%x\n", dh->dataOff);
	}
	printf("\n[] Number of classes in the archive: %d\n", dh->classDefsSize);
	string_id_list	= (struct StringID*)(dexBuf + dh->stringIdsOff);
	type_id_list		= (struct TypeID*)(dexBuf + dh->typeIdsOff);
	method_id_list	= (struct MethodID*)(dexBuf + dh->methodIdsOff);
	/* Parse class definations */
	//	for(j = 1; j <= 13/*dh.classDefsSize*/; j++) {
	for(j = 1; j <= dh->classDefsSize; j++) {
		//offset = dexOffset + dh.classDefsOff + j*sizeof(struct ClassDefine);
		offset = dh->classDefsOff + (j-1)*sizeof(struct ClassDefine);
		dexClassParse(dexBuf, offset, string_id_list, type_id_list, method_id_list);
		printf("[] Class %d ", j);
	}
	printf("Finished.\n");
}
#endif
uint getCodeOffset(ushort type, uchar* bitmap, uint* offsets, uint mid, uint cid) {
	uint	i, j;
	uchar b;
	if(type == 2) // none compiled
		return 0;
	assert(offsets);
	i = mid % 8;
	j = mid / 8;
	if(type == 1) {
		b = bitmap[j];
		if( (b & (0x80 >> i)) == 0 )
			return 0;
	}
	// printf("%d %d 0x%x (0x%x)  0x%x  0x%x\n", j, i,
	//		b, (0x80>>i), mid, cid);
	return offsets[cid];
}


bool oatDexClassParse(uchar*dexBuf, uint offset,
		struct OatClassHeader *oat_class_header,
		struct StringID *string_id_list,
		struct TypeID *type_id_list,
		struct ProtoID *proto_id_list,
		struct FieldID *field_id_list,
		struct MethodID *method_id_list) {

	struct ClassDefine *class_def_item;

	uchar typeDesc[255];
	uchar classFile[255];
	uchar className[255];

	uchar returnType[255];
	uchar shorty[255];
	uchar params[255];
	uchar str[255];
	uchar buf[32];
	uchar *buffer, *ptr;

	int len = 0;
	int field_idx_diff;
	int field_access_flags;

	int method_idx_diff;
	int method_access_flags;
	int method_code_off;

	int key = 0, i = 0;

	uint  static_fields_size; 
	uint  instance_fields_size;
	uint  direct_methods_size;
	uint  virtual_methods_size;

	int size_uleb, size_uleb_value;

	uchar* bitmap = NULL;
	uint   bitmap_size = 0;
	uint*  methods_offsets = NULL;
	uint   native_code_offset = 0;
	uint   total_methods = 0;
	uint   native_methods = 0;

	struct OatQuickMethodHeader *oat_mth_header;
	struct DexHeader *dh = (struct DexHeader*)dexBuf;

	//printf("[] classDefOff: 0x%x\n", offset);
	class_def_item = (struct ClassDefine*)(dexBuf + offset);
	if(class_def_item->sourceFileId != NO_INDEX ){
		getClassFileName(dexBuf, string_id_list, class_def_item, classFile);
		//printf("( %s )\n", str);
	} else {
		strcpy(classFile, "Unknown");
	}
	/* Get the type description for the class */
	uint idOff = getTypeDescForClass(dexBuf, string_id_list, type_id_list, class_def_item, className);
	uchar *accessFlags = parseAccessFlags(class_def_item->accessFlags);

	/* The	bitmap field	is	a	bitmap	of	length	bitmap_size bytes	where	each	bit	indicates	whether	a	particular	
	 * method	is	compiled	or	not.		Each	bit	corresponds	to	a	method	in	the	class. If	type is	either	
	 * kOatClassAllCompiled or	kOatClassNoneCompiled,	there	will	be	no	bitmap_size and	bitmap fields	present	
	 * and	type is	immediately	followed	by	the	method_offsets.	If	type is	kOatClassSomeCompiled,	it	means	at	
	 * least	one	but	not	all	methods	are	compiled.	In	this	case,	the	method_offsets come	right	after	the	bitmap.	
	 * Each	bit	in	the	bitmap,	starting	from	the	least	significant	bit,	corresponds	to	a	method	in	this	class -
	 * direct_methods first,	followed	by	virtual_methods. They	are	in	the	same	order	as	they	appear in	the	
	 * class_data_item	of	this	class. For	every	set	bit,	there	will	be	a	corresponding	entry	in	method_offsets.
	 * 
	 * method_offsets is	a	list	of	offset	that	points	to	the	generated	native	code	for	each	compiled	method.	Note	
	 * that	for	OAT	files	with	OATHeader->instruction_set is kThumb2 (which	the	majority	of	the	OAT	files	you
	 * will	encounter	will	likely	be),	the	method	offsets will	have	their least	significant	bit	set.	For	instance,	
	 * if the offset is	0x00143061,	the	actual	start	of	the	native	code	is	at	offset	0x00143060.
	 */

	assert(oat_class_header != NULL);
	if(oat_class_header->type==0 || oat_class_header->type==1 
			|| oat_class_header->type==2 || oat_class_header->type==3) {
	} else {
		printf(" type: %d\n", oat_class_header->type);
		exit(1);
	}
	/* print oat related information */
	//printf("\toat class type: %s\n", OAT_CLASS_TYPE[oat_class_header->type]);
	if( oat_class_header->type == 1) {
		bitmap_size = *(uint*)((uchar*)oat_class_header + sizeof(struct OatClassHeader));
		bitmap = (uchar*)oat_class_header + sizeof(struct OatClassHeader) + sizeof(uint);
		methods_offsets = (uint*)(bitmap + bitmap_size);
	} else {
		methods_offsets = (uint*)((uchar*)oat_class_header + sizeof(struct OatClassHeader));
	}

	printf(": %s (%s) (type_idx=%d) (flags=%s) (%s)\n",
			className, classFile, class_def_item->classId,
			accessFlags, OAT_CLASS_TYPE[oat_class_header->type]);
#if 0
	/* print debug info */
	printf("\tclass_idx='0x%x':", class_def_item->classId);
	printf("( %s )\n", str);
	printf("\taccess_flags='0x%x'\n", class_def_item->accessFlags); /*need to interpret this*/
	printf("\tsuperclass_idx='0x%x':", class_def_item->superClassId);
	getTypeDesc(dexBuf, string_id_list, type_id_list, class_def_item->superClassId,str);
	printf("( %s )\n", str);
	printf("\tinterfaces_off='0x%x'\n", class_def_item->interfaceOff); /*need to look this up in the DexTypeList*/
	printf("\tsource_file_idx='0x%x'\n", class_def_item->sourceFileId);
#endif
#if 0
	if (class_def_item->sourceFileId != NO_INDEX)
	{
		getStringValue(dexBuf, string_id_list, class_def_item->sourceFileId, str); //causes a seg fault on some dex files
		printf("( %s )\n", str);
	}
#endif
	printf("\tannotations_off=0x%x\n", class_def_item->annotationsOff);
	printf("\tclass_data_off=0x%x (%d)\n", class_def_item->classDataOff, class_def_item->classDataOff);
	printf("\tstatic_values_off=0x%x (%d)\n", class_def_item->staticValuesOff, class_def_item->staticValuesOff);
	/* change position to classDataOff */
	if (class_def_item->classDataOff == 0) {
		if (DEBUG) {
			printf ("\t0 static fields\n");
			printf ("\t0 instance fields\n");
			printf ("\t0 direct methods\n");
		} else {
			printf ("0 direct methods, 0 virtual methods\n");
		}
		return false;
	} else {
		offset = class_def_item->classDataOff;
	}
	len = dh->mapOff - offset;
	if(len < 1) {
		len = dh->fileSize - offset;
		if(len < 1) {
			fprintf(stderr, "ERROR: invalid file length in dex header \n");
			exit(1);
		}
	}
	buffer = malloc(len);
	assert(buffer != NULL);
	memcpy(buffer, dexBuf+offset, len);
	ptr = buffer;
	static_fields_size = readUnsignedLeb128(&buffer);
	instance_fields_size = readUnsignedLeb128(&buffer);
	direct_methods_size = readUnsignedLeb128(&buffer);
	virtual_methods_size = readUnsignedLeb128(&buffer);

	if(DEBUG) printf("\t%d static fields\n", static_fields_size);

	key = 0;
	for(i = 0; i < static_fields_size; i++) {
		field_idx_diff = readUnsignedLeb128(&buffer);
		field_access_flags = readUnsignedLeb128(&buffer);

		/* fields */
		if (key == 0) key=field_idx_diff;
		ushort class_idx = field_id_list[key].classId;
		ushort type_idx = field_id_list[key].typeId;
		uint   name_idx  = field_id_list[key].nameId;
		
		offset = string_id_list[name_idx].stringDataOff;
		memcpy(buf, dexBuf+offset, 10);
		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		memcpy(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';
		
		if(DEBUG) {
			getTypeDesc(dexBuf, string_id_list, type_id_list, type_idx, typeDesc);
			printf ("\t\t[%d]: %s %s\t|--field_idx_diff='0x%x' |", i, typeDesc, str, field_idx_diff);
			printf (" |--field_access_flags='0x%x' : %s\n",field_access_flags,
					parseAccessFlags(field_access_flags));
		}
	}
	if (DEBUG) printf ("\t%d instance fields\n", instance_fields_size);
	for (i=0;i<instance_fields_size;i++) {
		field_idx_diff = readUnsignedLeb128(&buffer);
		field_access_flags = readUnsignedLeb128(&buffer);
		/* fields */
		if (key == 0) key=field_idx_diff;
		ushort class_idx = field_id_list[key].classId;
		ushort type_idx = field_id_list[key].typeId;
		uint   name_idx  = field_id_list[key].nameId;
		
		offset = string_id_list[name_idx].stringDataOff;
		memcpy(buf, dexBuf+offset, 10);
		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		memcpy(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';
		
		if (DEBUG) {
			getTypeDesc(dexBuf, string_id_list, type_id_list, type_idx, typeDesc);
			printf ("\t\t[%d]: %s %s |--field_idx_diff='0x%x'", i, typeDesc, str, field_idx_diff);
			printf (" |--field_access_flags='0x%x': %s\n",field_access_flags,
					parseAccessFlags(field_access_flags));
		}
	}

	if (!DEBUG) printf ("%d direct methods, %d virtual methods\n", direct_methods_size, virtual_methods_size);
	if (DEBUG) printf ("\t%d direct methods\n", direct_methods_size);

	key=0;
	for (i=0;i<direct_methods_size;i++) {
		method_idx_diff = readUnsignedLeb128(&buffer);
		method_access_flags = readUnsignedLeb128(&buffer);
		method_code_off = readUnsignedLeb128(&buffer);

		/* methods */
		if (key == 0) key=method_idx_diff;
		else key += method_idx_diff;

		ushort class_idx = method_id_list[key].classId;
		ushort proto_idx = method_id_list[key].protoId;
		uint   name_idx  = method_id_list[key].nameId;

		/* print method name ... should really do this stuff through a common function, its going to be annoying to debug this...:/ */
		offset = string_id_list[name_idx].stringDataOff;
		assert(buf != NULL);
		memcpy(buf, dexBuf+offset, 10);

		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		memcpy(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';

	  //getTypeDesc(dexBuf, string_id_list,type_id_list,class_idx, typeDesc);
		//getTypeDesc(dexBuf, string_id_list, proto_id_list, class_idx, typeDesc);
		getProtoDesc(dexBuf, string_id_list, type_id_list, proto_id_list,
				proto_idx, returnType, shorty, params);
		printf ("\tdirect method %d (method_id_idx=%d): %s %s(%s) %s\n",i+1, key,
				returnType, str, shorty, params);

		native_code_offset = getCodeOffset(oat_class_header->type, bitmap, methods_offsets,
				total_methods, native_methods);
		total_methods++;
		if(native_code_offset > 0)
		{
			printf("\t\tnative_code_off=0x%x\n", native_code_offset);
			native_methods++;
			oat_mth_header = (struct OatQuickMethodHeader*)(file_begin+native_code_offset-0x1c);
			printf("\t\t\tgc_map: 0x%x\n", oat_mth_header->gcMapOffset);
			printf("\t\t\tsize: %d\n", oat_mth_header->codeSize);
		}

		if (DEBUG) {
			printf("\t\tmethod_code_off=0x%x\n", method_code_off);
			printf("\t\tmethod_access_flags='0x%x': %s\n", method_access_flags,
					parseAccessFlags(method_access_flags));
			printf("\t\tclass_idx='0x%x'\n", class_idx);
			printf("\t\tproto_idx=0x%x\n", proto_idx);
		}
	}
	if (DEBUG) printf ("\t%d virtual methods\n", virtual_methods_size);

	key=0;
	for (i=0;i<virtual_methods_size;i++) {
		method_idx_diff = readUnsignedLeb128(&buffer);
		method_access_flags = readUnsignedLeb128(&buffer);
		method_code_off = readUnsignedLeb128(&buffer);

		/* methods */
		if (key == 0) key=method_idx_diff;
		else key += method_idx_diff;

		ushort class_idx = method_id_list[key].classId;
		ushort proto_idx = method_id_list[key].protoId;
		uint    name_idx  = method_id_list[key].nameId;

		/* print method name */
		offset=string_id_list[name_idx].stringDataOff;
		//printStringValue(string_id_list,name_idx,input,str,"%s\n");
		memcpy(buf, dexBuf+offset, 10);
		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		// offset2: on esta el tamany (size_uleb_value) en uleb32 de la string, seguit de la string 
		memcpy(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';
		
		//getTypeDesc(dexBuf, string_id_list,type_id_list,class_idx, typeDesc);
		getProtoDesc(dexBuf, string_id_list, type_id_list, proto_id_list,
				proto_idx, returnType, shorty, params);
		printf ("\tvirtual method %d (method_id_idx=%d): %s %s(%s) %s\n",i+1, key,
				returnType, str, shorty, params);

		native_code_offset = getCodeOffset(oat_class_header->type, bitmap, methods_offsets,
				total_methods, native_methods);
		total_methods++;
		if(native_code_offset > 0) {
			printf("\t\tnative_code_off=0x%x\n", native_code_offset);
			native_methods++;
			oat_mth_header = (struct OatQuickMethodHeader*)(file_begin+native_code_offset-0x1c);
			printf("\t\t\tgc_map: 0x%x\n", oat_mth_header->gcMapOffset);
			printf("\t\t\tsize: %d\n", oat_mth_header->codeSize);
		}

		if (DEBUG) {
			printf("\t\tmethod_code_off=0x%x\n", method_code_off);
			printf("\t\tmethod_access_flags='0x%x' %s\n", method_access_flags,
					parseAccessFlags(method_access_flags));	
			printf("\t\tclass_idx=0x%x\n", class_idx);
			printf("\t\tproto_idx=0x%x\n", proto_idx);
		}
	}
	free(ptr);
	return true;
}

/* methods */
bool oatDexFileParse(uchar* oatdata, 
		struct OatClassOffset* oat_class_offsets, 
		uchar* dexBuf, uint size) {
	uint j = 0;
	struct DexHeader *dh;

	struct OatClassHeader *oat_class_header;
	struct MethodID *method_id_list;
	struct FieldID	*field_id_list;
	struct StringID *string_id_list;
	struct TypeID   *type_id_list;
	struct ProtoID  *proto_id_list;

	uint  offset = 0;

	dh = (struct DexHeader*)dexBuf;
	//dump(fd, dexOffset+dex_file_offset, dh.fileSize);
	if (1) {
		printf("[] DEX magic: ");
		for(j=0;j<8;j++) printf("%02x ", dh->magic[j]);
		printf("\n");
		printf("[] DEX version: %s\n", &dh->magic[4]);
		printf("[] Adler32 checksum: 0x%x\n", dh->checksum);
		printf("[] Dex file size: %d\n", dh->fileSize);
		printf("[] Dex header size: %d bytes (0x%x)\n", dh->headerSize, dh->headerSize);
		printf("[] Endian Tag: 0x%x\n", dh->endianTag);
		printf("[] Link size: %d\n", dh->linkSize);
		printf("[] Link offset: 0x%x\n", dh->linkOff);
		printf("[] Map list offset: 0x%x\n", dh->mapOff);
		printf("[] Number of strings in string ID list: %d\n", dh->stringIdsSize);
		printf("[] String ID list offset: 0x%x\n", dh->stringIdsOff);
		printf("[] Number of types in the type ID list: %d\n", dh->typeIdsSize);
		printf("[] Type ID list offset: 0x%x\n", dh->typeIdsOff);
		printf("[] Number of items in the method prototype ID list: %d\n", dh->protoIdsSize);
		printf("[] Method prototype ID list offset: 0x%x\n", dh->protoIdsOff);
		printf("[] Number of item in the field ID list: %d\n", dh->fieldIdsSize);
		printf("[] Field ID list offset: 0x%x\n", dh->fieldIdsOff);
		printf("[] Number of items in the method ID list: %d\n", dh->methodIdsSize);
		printf("[] Method ID list offset: 0x%x\n", dh->methodIdsOff);
		printf("[] Number of items in the class definitions list: %d\n", dh->classDefsSize);
		printf("[] Class definitions list offset: 0x%x\n", dh->classDefsOff);
		printf("[] Data section size: %d bytes\n", dh->dataSize);
		printf("[] Data section offset: 0x%x\n", dh->dataOff);
	}
	printf("\n[] Number of classes in the archive: %d\n", dh->classDefsSize);

	string_id_list	= (struct StringID*)(dexBuf + dh->stringIdsOff);
	type_id_list		= (struct TypeID*)(dexBuf + dh->typeIdsOff);
	proto_id_list		= (struct ProtoID*)(dexBuf + dh->protoIdsOff);
	field_id_list   = (struct FieldID*)(dexBuf + dh->fieldIdsOff);
	method_id_list	= (struct MethodID*)(dexBuf + dh->methodIdsOff);
	/* Parse class definations */
	//for(j = 1; j <= 3138/*dh.classDefsSize*/; j++) {
  for(j = 1; j <= dh->classDefsSize; j++) {
		printf("Class %d: (offset=0x%08x)", j, oat_class_offsets[j-1].offset);
		//offset = dexOffset + dh.classDefsOff + j*sizeof(struct ClassDefine);
		oat_class_header = (struct OatClassHeader*)(oatdata + oat_class_offsets[j-1].offset);
		offset = dh->classDefsOff + (j-1)*sizeof(struct ClassDefine);
		assert((uchar*)oat_class_header+sizeof(struct OatClassHeader) < oatdata+size);
		oatDexClassParse(dexBuf, offset, oat_class_header, 
				string_id_list, type_id_list, proto_id_list, 
				field_id_list, method_id_list);
	}
	printf("Finished.\n");
	return true;
	}
