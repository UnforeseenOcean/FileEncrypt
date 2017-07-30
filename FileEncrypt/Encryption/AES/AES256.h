#ifndef AES256_ENCRYPTION_H_INCLUDED
#define AES256_ENCRYPTION_H_INCLUDED

#include "AESConstant.h"

namespace Encryption {
    namespace AES256 {
		void Cipher(BYTE srcBytes[16], const UINT32 srcExpandedKey[60]);
		void KeyExpansion(const BYTE srcKey[32], UINT32 dstExpandedKey[60]);
    }
}

#endif // AES256_ENCRYPTION_H_INCLUDED
