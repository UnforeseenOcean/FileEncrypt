#ifndef ENCRYPTION_AESCONSTANT_H_INCLUDED
#define ENCRYPTION_AESCONSTANT_H_INCLUDED

#include <windows.h>

namespace Encryption {
	extern const BYTE SBox[256];
	extern const UINT32 Rcon[11];
	extern const BYTE Multiply0x02[256];
	extern const BYTE Multiply0x03[256];
}

#endif	//ENCRYPTION_AESCONSTANT_H_INCLUDED