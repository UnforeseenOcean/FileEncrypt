#ifndef AES192_ENCRYPTION_H_INCLUDED
#define AES192_ENCRYPTION_H_INCLUDED

#include "AESConstant.h"

namespace Encryption {
    namespace AES192 {
		void Cipher(BYTE srcBytes[16], const UINT32 srcExpandedKey[52]);
		void KeyExpansion(const BYTE srcKey[24], UINT32 dstExpandedKey[52]);
    }
}

#endif // AES192_ENCRYPTION_H_INCLUDED
