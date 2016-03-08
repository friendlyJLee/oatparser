#ifndef _DEX_HEADER_H
#define _DEX_HEADER_H

#include <stdio.h>
#include <oatparse.h>

#define NO_INDEX 0xffffffff

struct DexHeader {
	uchar	magic[8];
	uint  checksum;
	uchar signature[20];
	uint  fileSize;
	uint  headerSize;
	uint  endianTag;
	uint  linkSize;
	uint  linkOff;
	uint  mapOff;
	uint  stringIdsSize;
	uint  stringIdsOff;
	uint  typeIdsSize;
	uint  typeIdsOff;
	uint  protoIdsSize;
	uint  protoIdsOff;
	uint  fieldIdsSize;
	uint  fieldIdsOff;
	uint  methodIdsSize;
	uint  methodIdsOff;
	uint  classDefsSize;
	uint  classDefsOff;
	uint  dataSize;
	uint  dataOff;
};

struct ClassDefine {
	uint  classId;
	uint  accessFlags;
	uint  superClassId;
	uint  interfaceOff;
	uint  sourceFileId;
	uint  annotationsOff;
	uint  classDataOff;
	uint  staticValuesOff;
};

struct MethodID {
	ushort  classId;
	ushort  protoId;
	uint		nameId;
};

struct FieldID {
	ushort classId;
	ushort typeId;
	uint   nameId;
};

struct StringID {
	uint stringDataOff;
};

struct TypeID {
	uint descriptorId;
};

struct ProtoID {
	/* index into the stringID list of the short-form descriptor of this
	 * prototype. The string must comform to the syntax for ShortyDescriptor,
	 * defined above. and much correspond to the return type and paramethers 
	 * of this item.
	 */
	uint shortyId;
	/* index info the TypeIDs list for the return type of this descriptor
	 */
	uint returnTypeId;
	/* offset from the start of the file to the list of parameter types of this prototype.
	 * or 0 if this prototype has no parameters. This offset, if non-zero, should be in 
	 * the data section, and the data threre thould be in the format specified by "type list" below.
	 * Additionally, there should be no reference to the type void in the list;
	 */
	uint parametersOff;
};

bool dexFileParse(uchar* dexBuf, uint size);
bool oatDexFileParse(uchar* oatdata, struct OatClassOffset* oat_class_offsets, uchar* dexBuf, uint size);


#endif // _DEX_HEADER_H
