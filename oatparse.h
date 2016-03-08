#ifndef _OAT_HEADER_H
#define _OAT_HEADER_H

#include <stdio.h>

#define DEBUG  1

typedef uint32_t	uint;
typedef uint16_t  ushort;
typedef uint8_t 	uchar;


struct OatSec {
	uint oatdata_offset;
	uint oatdata_size;
	uint oatexec_offset;
	uint oatexec_size;
	uint oatlastword_offset;
	uint oatlastword_size;
};

struct OatHeader {
	uchar  magic[4];
	uchar  version[4];
	uint  adler32Checksum;
	uint  instructionSet;
	uint  instructionSetFeatures;
	uint  dexFileCount;
	uint  executableOffset;
	uint  interpreterToInterpreterBridgeOffset;
	uint  interpreterToCompiledCodeBridgeOffset;
	uint  jniDlsymLookupOffset;
	uint  quickGenericJniTrampolineOffset;
	uint  quickImtConflictTrampolineOffset;
	uint  quickResolutionTrampolineOffset;
	uint  quickToInterpreterBridgeOffset;				
	uint  imagePatchDelta;											// The image relocated address delta
	uint  imageFileLocationOatChecksum;					// Adler-32 checksum of boot.oat's header
	uint  imageFileLocationOatDataBegin;				// The virtual address of boot.oat's oatdata section
	uint  keyValueStoreSize;										// The length of key_value_store
};

typedef enum {
	kOatClassAllCompiled = 0, 
	kOatClassSomeCompiled = 1,
	kOatClassNoneCompiled = 2,
	kOatClassMax = 3
} OatClassType;

typedef enum {
	kNone,
	kArm,
	kArm64,
	kThumb2,
	kX86,
	kX86_64,
	kMips,
	kMips64
} InstructionSet;

struct OatQuickMethodHeader {
	uint mappingTableOffset;
	uint vmapTableOffset;
	uint gcMapOffset;
	uint QuickMethodFrameInfo_frame_size_in_bytes;
	uint QuickMethodFrameInfo_core_spill_mask;
	uint QuickMethodFremeInfo_fp_spill_mask;
	uint codeSize;
};

struct OatClassOffset {
	uint offset;
};

struct OatClassHeader {
	unsigned short status; // State of class during compilation
	unsigned short type;   // Type of class
//	uint	 bitmapSize;				 // Size of compiled methods bitmap (present only wehen type==1)
};
#endif // _OAT_HEADER_H
