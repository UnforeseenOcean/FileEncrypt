#include <tchar.h>
#include <windows.h>
#include <string>

#include "SHA256.h"
#include "Encryption/AES/AES128.h"
#include "Encryption/AES/AES192.h"
#include "Encryption/AES/AES256.h"
#include "Decryption/AES/AES128.h"
#include "Decryption/AES/AES192.h"
#include "Decryption/AES/AES256.h"

#ifdef UNICODE
typedef std::wstring _tString;
#else
typedef std::string _tString;
#endif

HANDLE ConsoleInputHandle = INVALID_HANDLE_VALUE;
HANDLE ConsoleOutputHandle = INVALID_HANDLE_VALUE;

enum EncryptType { AES128, AES192, AES256 };

BOOL GetConsoleIOHandle() {
	if (ConsoleInputHandle == INVALID_HANDLE_VALUE) {
		ConsoleInputHandle = GetStdHandle(STD_INPUT_HANDLE);
		if (ConsoleInputHandle == INVALID_HANDLE_VALUE) return FALSE;
	}

	if (ConsoleOutputHandle == INVALID_HANDLE_VALUE) {
		ConsoleOutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (ConsoleInputHandle == INVALID_HANDLE_VALUE) return FALSE;
	}

	return TRUE;
}

_tString GetPassword() {
	_tString ret;

	if (GetConsoleIOHandle() == FALSE) return ret;

	DWORD OldConsoleMode = 0;
	if (GetConsoleMode(ConsoleInputHandle, &OldConsoleMode) == FALSE) return ret;
	if (SetConsoleMode(ConsoleInputHandle, OldConsoleMode & ~ENABLE_ECHO_INPUT & ~ENABLE_LINE_INPUT) == FALSE) return ret;

	DWORD count = 0;
	_TCHAR charGotten = 0;
	WriteConsole(ConsoleOutputHandle, TEXT("Password:>"), 10, &count, NULL);
	while (ReadConsole(ConsoleInputHandle, &charGotten, 1, &count, NULL) && 
		   count == 1 && 
		   charGotten != TEXT('\r') && 
		   charGotten != TEXT('\n')) {

		if (charGotten == TEXT('\b')) {
			if (ret.length() != 0) {
				ret.pop_back();
				WriteConsole(ConsoleOutputHandle, TEXT("\b \b"), 3, &count, NULL);
			}
		} else {
			WriteConsole(ConsoleOutputHandle, TEXT("*"), 1, &count, NULL);
			ret.push_back(charGotten);
		}
	}

	SetConsoleMode(ConsoleInputHandle, OldConsoleMode);
	WriteConsole(ConsoleOutputHandle, TEXT("\r\n"), 2, &count, NULL);

	return ret;
}

#ifdef _DEBUG
void OutputHashString(const BYTE* srcBytes, UINT64 srcBytesLength) {

//#define USE_LOWERCASE
#ifdef USE_LOWERCASE
	static _TCHAR transTable[] = { TEXT('0'), TEXT('1'), TEXT('2'), TEXT('3'),
								   TEXT('4'), TEXT('5'), TEXT('6'), TEXT('7'),
								   TEXT('8'), TEXT('9'), TEXT('a'), TEXT('b'),
								   TEXT('c'), TEXT('d'), TEXT('e'), TEXT('f')
};
#else
	static _TCHAR transTable[] = { TEXT('0'), TEXT('1'), TEXT('2'), TEXT('3'),
								   TEXT('4'), TEXT('5'), TEXT('6'), TEXT('7'),
								   TEXT('8'), TEXT('9'), TEXT('A'), TEXT('B'),
								   TEXT('C'), TEXT('D'), TEXT('E'), TEXT('F')};
#endif

	SHA256::SHA256HashResult HashResult = SHA256::GetHash(srcBytes, srcBytesLength);
	SHA256::ToBigEndian(HashResult);

	_TCHAR outputString[65] = {};;
	for (UINT i = 0; i < 32; ++i) {
		outputString[i << 1] = transTable[((unsigned char*)&HashResult)[i] >> 4];
		outputString[(i << 1) + 1] = transTable[((unsigned char*)&HashResult)[i] & 0x0F];
	}
	outputString[64] = 0;

	
	if (GetConsoleIOHandle() == FALSE) return;
	DWORD count = 0;
	WriteConsole(ConsoleOutputHandle, TEXT("\r\n\r\nPassword hash: "), 19, &count, NULL);
	WriteConsole(ConsoleOutputHandle, outputString, 64, &count, NULL);
	WriteConsole(ConsoleOutputHandle, TEXT("\r\n"), 2, &count, NULL);
}
#endif // _DEBUG


BOOL encryptFile(const _tString& password, 
				 _TCHAR* inputfile, 
				 _TCHAR* outputfile, 
				 EncryptType encryptType = EncryptType::AES256) {

	_tString input_file(inputfile);
	_tString output_file = outputfile == nullptr ? _tString(input_file + TEXT(".encrypt")) : _tString(outputfile);
	
	//Generate AES cipher key.
	SHA256::SHA256HashResult hashdata= SHA256::GetHash((BYTE*)password.c_str(), password.length() * sizeof(_TCHAR));
	SHA256::ToBigEndian(hashdata);
	UINT32 ExpandedKey[60] = { 0 };

	void(*CipherFunc)(BYTE*, const UINT32*) = nullptr;
	switch(encryptType) {
		case EncryptType::AES128:
			Encryption::AES128::KeyExpansion((const BYTE*)&hashdata, ExpandedKey);
			CipherFunc = Encryption::AES128::Cipher;
			break;
		case EncryptType::AES192:
			Encryption::AES192::KeyExpansion((const BYTE*)&hashdata, ExpandedKey);
			CipherFunc = Encryption::AES192::Cipher;
			break;
		case EncryptType::AES256:
			Encryption::AES256::KeyExpansion((const BYTE*)&hashdata, ExpandedKey);
			CipherFunc = Encryption::AES256::Cipher;
			break;
		default:
			return FALSE;
	}

	// Open file.
	DWORD count = 0;
	HANDLE h_input_file = CreateFile(input_file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_input_file == INVALID_HANDLE_VALUE) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not open file.\r\ninput_filename: "), 29, &count, NULL);
		WriteConsole(ConsoleOutputHandle, input_file.c_str(), input_file.length(), &count, NULL);
		return FALSE;
	}

	LARGE_INTEGER input_file_size = { 0 };
	if (GetFileSizeEx(h_input_file, &input_file_size) == FALSE) {
		CloseHandle(h_input_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not get file size.\r\n"), 33, &count, NULL);
		return FALSE;
	}

	HANDLE h_output_file = CreateFile(output_file.c_str(), GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_output_file == INVALID_HANDLE_VALUE) {
		CloseHandle(h_input_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not create file.\r\nonput_filename: "), 31, &count, NULL);
		WriteConsole(ConsoleOutputHandle, output_file.c_str(), output_file.length(), &count, NULL);
		return FALSE;
	}

	// Create buffer
#define BUFFER_SIZE 50 * 1024 * 1024
	BYTE* tempBuffer = new BYTE[BUFFER_SIZE + 16];
	if (tempBuffer == nullptr) {
		CloseHandle(h_input_file);
		CloseHandle(h_output_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not allocate tempBuffer.\r\n"), 39, &count, NULL);
		return FALSE;
	}

	SetFilePointer(h_input_file, 0, NULL, FILE_BEGIN);
	SetFilePointer(h_output_file, 0, NULL, FILE_BEGIN);
	auto rounds = input_file_size.QuadPart / (BUFFER_SIZE);
	auto timesPerRound = BUFFER_SIZE >> 4;
	DWORD BytesReadOrWritten = 0;
	for (decltype(rounds) i = 0; i < rounds; ++i) {
		if (ReadFile(h_input_file, tempBuffer, BUFFER_SIZE, &BytesReadOrWritten, NULL) && BytesReadOrWritten == BUFFER_SIZE) {
			for (decltype(timesPerRound) j = 0; j < timesPerRound; ++j)
				CipherFunc(tempBuffer + (j << 4), ExpandedKey);
			
			if (!(WriteFile(h_output_file, tempBuffer, BUFFER_SIZE, &BytesReadOrWritten, NULL) && BytesReadOrWritten == BUFFER_SIZE)) {
				delete[] tempBuffer;
				CloseHandle(h_input_file);
				CloseHandle(h_output_file);
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when write file.\r\n"), 39, &count, NULL);
				return FALSE;
			}
		} else {
			delete[] tempBuffer;
			CloseHandle(h_input_file);
			CloseHandle(h_output_file);
			WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when read file.\r\n"), 38, &count, NULL);
			return FALSE;
		}
	}

	DWORD leftLength = (DWORD)(input_file_size.QuadPart - rounds * BUFFER_SIZE);
	if (ReadFile(h_input_file, tempBuffer, leftLength, &BytesReadOrWritten, NULL) && BytesReadOrWritten == leftLength) {
		auto final_times = leftLength >> 4;
		for (decltype(final_times) i = 0; i < final_times; ++i)
			CipherFunc(tempBuffer + (i << 4), ExpandedKey);
		
		auto finalLength = leftLength & 0xF;
		auto PaddingStart = tempBuffer + leftLength;
		if (finalLength > 8) {
			auto PaddingEnd = tempBuffer + ((final_times + 1) << 4) + 8;
			for (; PaddingStart != PaddingEnd; ++PaddingStart)
				*PaddingStart = 0;
			*(decltype(LARGE_INTEGER::QuadPart)*)PaddingEnd = input_file_size.QuadPart;

			CipherFunc(tempBuffer + (final_times << 4), ExpandedKey);
			CipherFunc(tempBuffer + ((final_times + 1) << 4), ExpandedKey);

			if (!(WriteFile(h_output_file, tempBuffer, (final_times + 2) << 4, &BytesReadOrWritten, NULL) && BytesReadOrWritten == ((final_times + 2) << 4))) {
				delete[] tempBuffer;
				CloseHandle(h_input_file);
				CloseHandle(h_output_file);
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when write file.\r\n"), 39, &count, NULL);
				return FALSE;
			}
		} else {
			auto PaddingEnd = tempBuffer + (final_times << 4) + 8;
			for (; PaddingStart != PaddingEnd; ++PaddingStart)
				*PaddingStart = 0;
			*(decltype(LARGE_INTEGER::QuadPart)*)PaddingEnd = input_file_size.QuadPart;

			CipherFunc(tempBuffer + (final_times << 4), ExpandedKey);

			if (!(WriteFile(h_output_file, tempBuffer, (final_times + 1) << 4, &BytesReadOrWritten, NULL) && BytesReadOrWritten == ((final_times + 1) << 4))) {
				delete[] tempBuffer;
				CloseHandle(h_input_file);
				CloseHandle(h_output_file);
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when write file.\r\n"), 39, &count, NULL);
				return FALSE;
			}
		}
	} else {
		delete[] tempBuffer;
		CloseHandle(h_input_file);
		CloseHandle(h_output_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when read file.\r\n"), 38, &count, NULL);
		return FALSE;
	}

	delete[] tempBuffer;
	CloseHandle(h_input_file);
	CloseHandle(h_output_file);
	return TRUE;
}

BOOL decryptFile(const _tString& password,
				 _TCHAR* inputfile,
				 _TCHAR* outputfile,
				 EncryptType encryptType = EncryptType::AES256) {

	_tString input_file(inputfile);
	_tString output_file = outputfile == nullptr ? _tString(inputfile) : _tString(outputfile);
	if (outputfile == nullptr) {
		_tString wordKey(TEXT(".encrypt"));
		_tString::size_type found = output_file.rfind(wordKey);
		if (found != _tString::npos) {
			output_file.replace(found, wordKey.length(), TEXT(""));
		} else {
			output_file += TEXT(".decrypt");
		}
	}

	//Generate AES cipher key.
	SHA256::SHA256HashResult hashdata = SHA256::GetHash((BYTE*)password.c_str(), password.length() * sizeof(_TCHAR));
	SHA256::ToBigEndian(hashdata);
	UINT32 ExpandedKey[60] = { 0 };

	void(*InverseCipherFunc)(BYTE*, const UINT32*) = nullptr;
	switch (encryptType) {
		case EncryptType::AES128:
			Decryption::AES128::KeyExpansion((const BYTE*)&hashdata, ExpandedKey);
			InverseCipherFunc = Decryption::AES128::InverseCipher;
			break;
		case EncryptType::AES192:
			Decryption::AES192::KeyExpansion((const BYTE*)&hashdata, ExpandedKey);
			InverseCipherFunc = Decryption::AES192::InverseCipher;
			break;
		case EncryptType::AES256:
			Decryption::AES256::KeyExpansion((const BYTE*)&hashdata, ExpandedKey);
			InverseCipherFunc = Decryption::AES256::InverseCipher;
			break;
		default:
			return FALSE;
	}

	// Open file.
	DWORD count = 0;
	HANDLE h_input_file = CreateFile(input_file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_input_file == INVALID_HANDLE_VALUE) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not open file.\r\ninput_filename: "), 45, &count, NULL);
		WriteConsole(ConsoleOutputHandle, input_file.c_str(), input_file.length(), &count, NULL);
		return FALSE;
	}

	LARGE_INTEGER input_file_size = { 0 };
	if (GetFileSizeEx(h_input_file, &input_file_size) == FALSE) {
		CloseHandle(h_input_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not get file size.\r\n"), 33, &count, NULL);
		return FALSE;
	}
	if (input_file_size.QuadPart % 16 != 0) {
		CloseHandle(h_input_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Input file's size is not correct.\r\n"), 42, &count, NULL);
		return FALSE;
	}

	HANDLE h_output_file = CreateFile(output_file.c_str(), GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_output_file == INVALID_HANDLE_VALUE) {
		CloseHandle(h_input_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not create file.\r\nonput_filename: "), 31, &count, NULL);
		WriteConsole(ConsoleOutputHandle, output_file.c_str(), output_file.length(), &count, NULL);
		return FALSE;
	}

	// Create buffer
	BYTE* tempBuffer = new BYTE[BUFFER_SIZE + 16];
	if (tempBuffer == nullptr) {
		CloseHandle(h_input_file);
		CloseHandle(h_output_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Could not allocate tempBuffer.\r\n"), 39, &count, NULL);
		return FALSE;
	}

	SetFilePointer(h_input_file, 0, NULL, FILE_BEGIN);
	SetFilePointer(h_output_file, 0, NULL, FILE_BEGIN);

	auto rounds = input_file_size.QuadPart / (BUFFER_SIZE);
	auto timesPerRound = BUFFER_SIZE >> 4;
	DWORD BytesReadOrWritten = 0;
	for (decltype(rounds) i = 0; i < rounds; ++i) {
		if (ReadFile(h_input_file, tempBuffer, BUFFER_SIZE, &BytesReadOrWritten, NULL) && BytesReadOrWritten == BUFFER_SIZE) {
			for (decltype(timesPerRound) j = 0; j < timesPerRound; ++j)
				InverseCipherFunc(tempBuffer + (j << 4), ExpandedKey);

			if (!(WriteFile(h_output_file, tempBuffer, BUFFER_SIZE, &BytesReadOrWritten, NULL) && BytesReadOrWritten == BUFFER_SIZE)) {
				delete[] tempBuffer;
				CloseHandle(h_input_file);
				CloseHandle(h_output_file);
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when write file.\r\n"), 39, &count, NULL);
				return FALSE;
			}
		} else {
			delete[] tempBuffer;
			CloseHandle(h_input_file);
			CloseHandle(h_output_file);
			WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when read file.\r\n"), 38, &count, NULL);
			return FALSE;
		}
	}

	DWORD leftLength = (DWORD)(input_file_size.QuadPart - rounds * BUFFER_SIZE);
	if (ReadFile(h_input_file, tempBuffer, leftLength, &BytesReadOrWritten, NULL) && BytesReadOrWritten == leftLength) {
		auto final_times = leftLength >> 4;
		for (decltype(final_times) i = 0; i < final_times; ++i)
			InverseCipherFunc(tempBuffer + (i << 4), ExpandedKey);

		LARGE_INTEGER output_file_size = { 0 };
		output_file_size.QuadPart = *(decltype(LARGE_INTEGER::QuadPart)*)(tempBuffer + ((final_times - 1) << 4) + 8);

		auto PaddedLength = input_file_size.QuadPart - output_file_size.QuadPart;
		if (!(PaddedLength >= 8 && PaddedLength <= 23)) {
			delete[] tempBuffer;
			CloseHandle(h_input_file);
			CloseHandle(h_output_file);
			WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when decrypt file.\r\n"), 41, &count, NULL);
			return FALSE;
		}

		DWORD final_part_size = (DWORD)(output_file_size.QuadPart - rounds * BUFFER_SIZE);
		if (!(WriteFile(h_output_file, tempBuffer, final_part_size, &BytesReadOrWritten, NULL) && BytesReadOrWritten == final_part_size)) {
			delete[] tempBuffer;
			CloseHandle(h_input_file);
			CloseHandle(h_output_file);
			WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when write file.\r\n"), 39, &count, NULL);
			return FALSE;
		}
	} else {
		delete[] tempBuffer;
		CloseHandle(h_input_file);
		CloseHandle(h_output_file);
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Error occured when read file.\r\n"), 38, &count, NULL);
		return FALSE;
	}

	delete[] tempBuffer;
	CloseHandle(h_input_file);
	CloseHandle(h_output_file);
	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[]) {
	if (GetConsoleIOHandle() == FALSE) return GetLastError();
	DWORD count = 0;

	if (argc == 1) {
		_tString helpString(
			TEXT("\r\n") \
			TEXT("Usage:\r\n") \
			TEXT("    fileEncrypt [-d] [-a encrypt_algorithm] input_filename [output_filename]\r\n") \
			TEXT("\r\n") \
			TEXT("Options:\r\n") \
			TEXT("    -d                    If specified, decrypt input_filename.\r\n") \
			TEXT("\r\n") \
			TEXT("    -a encrypt_algorithm  Specify hash algorithm that will be applied to your password input.\r\n") \
			TEXT("                          encrypt_algorithm can be \"aes128\", \"aes192\" and \"aes256\".\r\n") \
			TEXT("                          If not specified, the default value of encrypt_algorithm is \"aes256\".\r\n") \
			TEXT("\r\n") \
			TEXT("    input_filename        The filename of the file your want to encrypt.\r\n") \
			TEXT("\r\n") \
			TEXT("    output_filename       The filename of the output(encrypted) file.\r\n\r\n"));
		WriteConsole(ConsoleOutputHandle, helpString.c_str(), helpString.length(), &count, NULL);
		return 0;
	} else if (argc == 2) {
		_tString pass = GetPassword();

#ifdef _DEBUG
		OutputHashString((const BYTE*)pass.c_str(), pass.length() * sizeof(_TCHAR));
#endif

		return encryptFile(pass, argv[1], nullptr) == FALSE ? GetLastError() : 0;
	} else if (argc == 3) {
		_tString argv_1(argv[1]);
		_tString pass = GetPassword();

#ifdef _DEBUG
		OutputHashString((const BYTE*)pass.c_str(), pass.length() * sizeof(_TCHAR));
#endif

		if (argv_1 == TEXT("-d")) {
			return decryptFile(pass, argv[2], nullptr) == FALSE ? GetLastError() : 0;
		} else {
			return encryptFile(pass, argv[1], argv[2]) == FALSE ? GetLastError() : 0;
		}
	} else if (argc == 4) {
		_tString argv_1(argv[1]);
		_tString argv_2(argv[2]);
		_tString pass = GetPassword();

#ifdef _DEBUG
		OutputHashString((const BYTE*)pass.c_str(), pass.length() * sizeof(_TCHAR));
#endif

		if (argv_1 == TEXT("-d")) {
			return decryptFile(pass, argv[2], argv[3]) == FALSE ? GetLastError() : 0;
		} else if(argv_1 == TEXT("-a")) {
			if (argv_2 == TEXT("aes128"))
				return encryptFile(pass, argv[3], nullptr, EncryptType::AES128) == FALSE ? GetLastError() : 0;
			else if (argv_2 == TEXT("aes192"))
				return encryptFile(pass, argv[3], nullptr, EncryptType::AES192) == FALSE ? GetLastError() : 0;
			else if (argv_2 == TEXT("aes256"))
				return encryptFile(pass, argv[3], nullptr, EncryptType::AES256) == FALSE ? GetLastError() : 0;
			else {
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Unknown algorithm.\r\n"), 27, &count, NULL);
				return 0;
			}
		}
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Parameter error.\r\n"), 25, &count, NULL);
		return 0;
	} else if (argc == 5) {
		_tString pass = GetPassword();

#ifdef _DEBUG
		OutputHashString((const BYTE*)pass.c_str(), pass.length() * sizeof(_TCHAR));
#endif

		if (_tString(argv[1]) == TEXT("-d") && _tString(argv[2]) == TEXT("-a")) {
			_tString argv_3(argv[3]);
			if (argv_3 == TEXT("aes128"))
				return decryptFile(pass, argv[4], nullptr, EncryptType::AES128) == FALSE ? GetLastError() : 0;
			else if (argv_3 == TEXT("aes192"))
				return decryptFile(pass, argv[4], nullptr, EncryptType::AES192) == FALSE ? GetLastError() : 0;
			else if (argv_3 == TEXT("aes256"))
				return decryptFile(pass, argv[4], nullptr, EncryptType::AES256) == FALSE ? GetLastError() : 0;
			else {
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Unknown algorithm.\r\n"), 27, &count, NULL);
				return 0;
			}
		} else if(_tString(argv[1]) == TEXT("-a")) {
			_tString argv_2(argv[2]);
			if (argv_2 == TEXT("aes128"))
				return encryptFile(pass, argv[3], argv[4], EncryptType::AES128) == FALSE ? GetLastError() : 0;
			else if (argv_2 == TEXT("aes192"))
				return encryptFile(pass, argv[3], argv[4], EncryptType::AES192) == FALSE ? GetLastError() : 0;
			else if (argv_2 == TEXT("aes256"))
				return encryptFile(pass, argv[3], argv[4], EncryptType::AES256) == FALSE ? GetLastError() : 0;
			else {
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Unknown algorithm.\r\n"), 27, &count, NULL);
				return 0;
			}
		}
	} else if (argc == 6) {
		_tString pass = GetPassword();

#ifdef _DEBUG
		OutputHashString((const BYTE*)pass.c_str(), pass.length() * sizeof(_TCHAR));
#endif

		if (_tString(argv[1]) == TEXT("-d") && _tString(argv[2]) == TEXT("-a")) {
			_tString argv_3(argv[3]);
			if (argv_3 == TEXT("aes128"))
				return decryptFile(pass, argv[4], argv[5], EncryptType::AES128) == FALSE ? GetLastError() : 0;
			else if (argv_3 == TEXT("aes192"))
				return decryptFile(pass, argv[4], argv[5], EncryptType::AES192) == FALSE ? GetLastError() : 0;
			else if (argv_3 == TEXT("aes256"))
				return decryptFile(pass, argv[4], argv[5], EncryptType::AES256) == FALSE ? GetLastError() : 0;
			else {
				WriteConsole(ConsoleOutputHandle, TEXT("Error: Unknown algorithm.\r\n"), 27, &count, NULL);
				return 0;
			}
		}
		WriteConsole(ConsoleOutputHandle, TEXT("Error: Parameter error.\r\n"), 25, &count, NULL);
		return 0;
	}

	WriteConsole(ConsoleOutputHandle, TEXT("Error: Parameter error.\r\n"), 25, &count, NULL);
	return 0;
}