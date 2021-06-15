#include "pch.h"
#include "MyAES.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

MyAES::MyAES()
{
}

MyAES::~MyAES()
{
}

hstring MyAES::Key()
{
	return CryptographicBuffer::EncodeToHexString(CryptographicBuffer::CreateFromByteArray(this->Key128));
}

void MyAES::Key(hstring& iData)
{
	com_array<uint8_t> key;
	CryptographicBuffer::CopyToByteArray(CryptographicBuffer::DecodeFromHexString(iData), key);
	for (size_t i = 0; i < 16; i++)
	{
		this->Key128[i] = key.at(i);
	}
}

hstring MyAES::IV()
{
	return CryptographicBuffer::EncodeToHexString(CryptographicBuffer::CreateFromByteArray(this->IV128));
}

void MyAES::IV(hstring& iData)
{
	com_array<uint8_t> iv;
	CryptographicBuffer::CopyToByteArray(CryptographicBuffer::DecodeFromHexString(iData), iv);
	for (size_t i = 0; i < 16; i++)
	{
		this->IV128[i] = iv.at(i);
	}
}

void MyAES::GenerateSymmetricKey128()
{
	GenerateRandom128(this->Key128);
}

void MyAES::GenerateSymmetricKey128(const hstring key)
{
	int i = 0;
	time_t t;
	srand(time(&t));
	for each (uint8_t item in to_string(key))
	{
		Key128[i++] = item;
	}
	while (i<16)
	{
		Key128[i++] = rand();
	}
}

hstring MyAES::AESCBC(const IBuffer& iData, bool encrypt)
{
	hstring oText = L"";
	uint8_t iBlock128[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t oBlock128[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t IV[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	DataReader dr = DataReader::FromBuffer(iData);
	if (encrypt)
	{
		GenerateRandom128(this->IV128);
	}
	for (size_t i = 0; i < 16; i++)
	{
		IV[i] = IV128[i];
	}
	while (dr.UnconsumedBufferLength() > 0)
	{
		uint32_t UCBL = dr.UnconsumedBufferLength();
		for (size_t i = 0; i < min(16u, UCBL); i++)
		{
			iBlock128[i] = dr.ReadByte();
		}
		if (encrypt)
		{
			XOR128(IV, iBlock128);
			AES128Encrypt(IV, IV, this->Key128);
			oText = oText + CryptographicBuffer::EncodeToHexString(CryptographicBuffer::CreateFromByteArray(IV));
		}
		else
		{
			AES128Decrypt(iBlock128, oBlock128, this->Key128);
			XOR128(oBlock128, IV);
			for (size_t i = 0; i < 16; i++)
			{
				IV[i] = iBlock128[i];
			}
			oText = oText + CryptographicBuffer::ConvertBinaryToString(BinaryStringEncoding::Utf8, CryptographicBuffer::CreateFromByteArray(oBlock128));
		}
	}
	return oText;
}

uint8_t MyAES::PerformSbox(uint8_t iByte)
{
	uint8_t row = 0;
	uint8_t column = 0;
	row = iByte >> 4;
	column = iByte & 0x0F;
	return S[row][column];
}

uint8_t MyAES::PerformiSbox(uint8_t iByte)
{
	uint8_t row = 0;
	uint8_t column = 0;
	row = iByte >> 4;
	column = iByte & 0x0F;
	return iS[row][column];
}

uint32_t MyAES::T(uint32_t w, uint8_t round)
{
	uint32_t tempw = 0;
	uint32_t Rcon[10] = { 0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1B000000,0x36000000 };
	w = (w >> 24) | (w << 8);
	tempw = tempw | PerformSbox(w >> 24);
	tempw = tempw << 8;
	tempw = tempw | PerformSbox(w >> 16);
	tempw = tempw << 8;
	tempw = tempw | PerformSbox(w >> 8);
	tempw = tempw << 8;
	tempw = tempw | PerformSbox(w);
	tempw = tempw ^ Rcon[round];
	return tempw;
}

void MyAES::KeyExpansion(const uint8_t(&K)[4][4], uint32_t(&w)[44])
{
	//build w[0-3]
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			w[column] = w[column] | K[row][column];
			if (row < 3)
			{
				w[column] = w[column] << 8;
			}
		}
	}
	//expand keys
	uint8_t round = 0;
	for (size_t i = 4; i < 44; i++)
	{
		if (i % 4 != 0)
		{
			w[i] = w[i - 4] ^ w[i - 1];
		}
		else
		{
			w[i] = w[i - 4] ^ T(w[i - 1], round++);
		}
	}
}

void MyAES::RoundKeyAdd(uint32_t(&w)[4], uint8_t(&s)[4][4])
{
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			s[row][column] = s[row][column] ^ (w[column] >> (24 - row * 8));
		}
	}
}

uint8_t MyAES::Multi2GF2_8(uint8_t iData)
{
	iData = iData << 1;
	if ((iData & 0x80) != 0)//if a_7=1
	{
		return iData ^ 0x1B;
	}
	else
	{
		return iData;
	}
}

uint8_t MyAES::Multi3GF2_8(uint8_t iData)
{
	return Multi2GF2_8(iData) ^ iData;
}

uint8_t MyAES::Multi9GF2_8(uint8_t iData)
{
	return Multi2GF2_8(Multi2GF2_8(Multi2GF2_8(iData))) ^ iData;
}

uint8_t MyAES::MultiBGF2_8(uint8_t iData)
{
	return Multi9GF2_8(iData) ^ Multi2GF2_8(iData);
}

uint8_t MyAES::MultiDGF2_8(uint8_t iData)
{
	return Multi9GF2_8(iData) ^ Multi2GF2_8(Multi2GF2_8(iData));
}

uint8_t MyAES::MultiEGF2_8(uint8_t iData)
{
	return Multi2GF2_8(Multi2GF2_8(Multi2GF2_8(iData))) ^ Multi2GF2_8(Multi2GF2_8(iData)) ^ Multi2GF2_8(iData);
}

void MyAES::ColumnMixture(uint8_t(&S)[4][4])
{
	uint8_t SS[4][4] = { {0,0,0,0},{0,0,0,0} ,{0,0,0,0} ,{0,0,0,0} };
	for (size_t column = 0; column < 4; column++)
	{
		SS[0][column] = Multi2GF2_8(S[0][column]) ^ Multi3GF2_8(S[1][column]) ^ S[2][column] ^ S[3][column];
		SS[1][column] = S[0][column] ^ Multi2GF2_8(S[1][column]) ^ Multi3GF2_8(S[2][column]) ^ S[3][column];
		SS[2][column] = S[0][column] ^ S[1][column] ^ Multi2GF2_8(S[2][column]) ^ Multi3GF2_8(S[3][column]);
		SS[3][column] = Multi3GF2_8(S[0][column]) ^ S[1][column] ^ S[2][column] ^ Multi2GF2_8(S[3][column]);
	}
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			S[row][column] = SS[row][column];
		}
	}
}

void MyAES::iColumnMixture(uint8_t(&S)[4][4])
{
	uint8_t SS[4][4] = { {0,0,0,0},{0,0,0,0} ,{0,0,0,0} ,{0,0,0,0} };
	for (size_t column = 0; column < 4; column++)
	{
		SS[0][column] = MultiEGF2_8(S[0][column]) ^ MultiBGF2_8(S[1][column]) ^ MultiDGF2_8(S[2][column]) ^ Multi9GF2_8(S[3][column]);
		SS[1][column] = Multi9GF2_8(S[0][column]) ^ MultiEGF2_8(S[1][column]) ^ MultiBGF2_8(S[2][column]) ^ MultiDGF2_8(S[3][column]);
		SS[2][column] = MultiDGF2_8(S[0][column]) ^ Multi9GF2_8(S[1][column]) ^ MultiEGF2_8(S[2][column]) ^ MultiBGF2_8(S[3][column]);
		SS[3][column] = MultiBGF2_8(S[0][column]) ^ MultiDGF2_8(S[1][column]) ^ Multi9GF2_8(S[2][column]) ^ MultiEGF2_8(S[3][column]);
	}
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			S[row][column] = SS[row][column];
		}
	}
}

void MyAES::AES128Encrypt(uint8_t iData128[16], uint8_t(&oData128)[16], uint8_t key128[16])
{
	uint8_t S[4][4] = { {0,0,0,0},{0,0,0,0} ,{0,0,0,0} ,{0,0,0,0} };
	uint8_t K[4][4] = { {0,0,0,0},{0,0,0,0} ,{0,0,0,0} ,{0,0,0,0} };
	uint32_t w[44] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint32_t w4[4] = { 0,0,0,0 };
	//build state matrix
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			S[row][column] = iData128[column * 4 + row];
		}
	}
	//build key matrix
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			K[row][column] = key128[column * 4 + row];
		}
	}
	//key expansion
	KeyExpansion(K, w);
	//first round key addition operation
	for (size_t i = 0; i < 4; i++)
	{
		w4[i] = w[i];
	}
	RoundKeyAdd(w4, S);
	//9 rounds 
	for (size_t round = 1; round < 10; round++)
	{
		//byte substitution
		for (size_t column = 0; column < 4; column++)
		{
			for (size_t row = 0; row < 4; row++)
			{
				S[row][column] = PerformSbox(S[row][column]);
			}
		}
		//line shift
		uint8_t temp = 0;
		//line1
		temp = S[1][0];
		S[1][0] = S[1][1];
		S[1][1] = S[1][2];
		S[1][2] = S[1][3];
		S[1][3] = temp;
		//line2
		temp = S[2][0];
		S[2][0] = S[2][1];
		S[2][1] = S[2][2];
		S[2][2] = S[2][3];
		S[2][3] = temp;
		temp = S[2][0];
		S[2][0] = S[2][1];
		S[2][1] = S[2][2];
		S[2][2] = S[2][3];
		S[2][3] = temp;
		//line3
		temp = S[3][3];
		S[3][3] = S[3][2];
		S[3][2] = S[3][1];
		S[3][1] = S[3][0];
		S[3][0] = temp;
		//column mixture
		ColumnMixture(S);
		//round key addition
		for (size_t i = 0; i < 4; i++)
		{
			w4[i] = w[round * 4 + i];
		}
		RoundKeyAdd(w4, S);
	}
	//round 10
	//byte substitution
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			S[row][column] = PerformSbox(S[row][column]);
		}
	}
	//line shift
	uint8_t temp = 0;
	//line1 << 1 byte
	temp = S[1][0];
	S[1][0] = S[1][1];
	S[1][1] = S[1][2];
	S[1][2] = S[1][3];
	S[1][3] = temp;
	//line2 << 2 bytes
	temp = S[2][0];
	S[2][0] = S[2][1];
	S[2][1] = S[2][2];
	S[2][2] = S[2][3];
	S[2][3] = temp;
	temp = S[2][0];
	S[2][0] = S[2][1];
	S[2][1] = S[2][2];
	S[2][2] = S[2][3];
	S[2][3] = temp;
	//line3 <<3 bytes = >> 1 byte
	temp = S[3][3];
	S[3][3] = S[3][2];
	S[3][2] = S[3][1];
	S[3][1] = S[3][0];
	S[3][0] = temp;
	//round key addition
	for (size_t i = 0; i < 4; i++)
	{
		w4[i] = w[40 + i];
	}
	RoundKeyAdd(w4, S);
	//get cyphertext from state matrix
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			oData128[column * 4 + row] = S[row][column];
		}
	}
}

void MyAES::AES128Decrypt(uint8_t iData128[16], uint8_t(&oData128)[16], uint8_t key128[16])
{
	uint8_t S[4][4] = { {0,0,0,0},{0,0,0,0} ,{0,0,0,0} ,{0,0,0,0} };
	uint8_t K[4][4] = { {0,0,0,0},{0,0,0,0} ,{0,0,0,0} ,{0,0,0,0} };
	uint32_t w[44] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint32_t w4[4] = { 0,0,0,0 };
	//build state matrix
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			S[row][column] = iData128[column * 4 + row];
		}
	}
	//build key matrix
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			K[row][column] = key128[column * 4 + row];
		}
	}
	//key expansion
	KeyExpansion(K, w);
	//first round key addition operation
	for (size_t i = 0; i < 4; i++)
	{
		w4[i] = w[40 + i];
	}
	RoundKeyAdd(w4, S);
	//9 rounds
	for (size_t round = 1; round < 10; round++)
	{
		//inverse line shift
		uint8_t temp = 0;
		//line1 >> 1 byte
		temp = S[1][3];
		S[1][3] = S[1][2];
		S[1][2] = S[1][1];
		S[1][1] = S[1][0];
		S[1][0] = temp;
		//line2 >> 2 bytes = << 2 bytes
		temp = S[2][0];
		S[2][0] = S[2][1];
		S[2][1] = S[2][2];
		S[2][2] = S[2][3];
		S[2][3] = temp;
		temp = S[2][0];
		S[2][0] = S[2][1];
		S[2][1] = S[2][2];
		S[2][2] = S[2][3];
		S[2][3] = temp;
		//line3 >> 3 bytes = << 1 byte
		temp = S[3][0];
		S[3][0] = S[3][1];
		S[3][1] = S[3][2];
		S[3][2] = S[3][3];
		S[3][3] = temp;
		//inverse byte substitution
		for (size_t column = 0; column < 4; column++)
		{
			for (size_t row = 0; row < 4; row++)
			{
				S[row][column] = PerformiSbox(S[row][column]);
			}
		}
		//round key addition
		for (size_t i = 0; i < 4; i++)
		{
			w4[i] = w[(10 - round) * 4 + i];
		}
		RoundKeyAdd(w4, S);
		//inverse column mixture
		iColumnMixture(S);
	}
	//round 10
	 //inverse line shift
	uint8_t temp = 0;
	//line1 >> 1 byte
	temp = S[1][3];
	S[1][3] = S[1][2];
	S[1][2] = S[1][1];
	S[1][1] = S[1][0];
	S[1][0] = temp;
	//line2 >> 2 bytes = << 2 bytes
	temp = S[2][0];
	S[2][0] = S[2][1];
	S[2][1] = S[2][2];
	S[2][2] = S[2][3];
	S[2][3] = temp;
	temp = S[2][0];
	S[2][0] = S[2][1];
	S[2][1] = S[2][2];
	S[2][2] = S[2][3];
	S[2][3] = temp;
	//line3 >> 3 bytes = << 1 byte
	temp = S[3][0];
	S[3][0] = S[3][1];
	S[3][1] = S[3][2];
	S[3][2] = S[3][3];
	S[3][3] = temp;
	//inverse byte substitution
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			S[row][column] = PerformiSbox(S[row][column]);
		}
	}
	//round key addition
	for (size_t i = 0; i < 4; i++)
	{
		w4[i] = w[i];
	}
	RoundKeyAdd(w4, S);
	//get plaintext from state matrix
	for (size_t column = 0; column < 4; column++)
	{
		for (size_t row = 0; row < 4; row++)
		{
			oData128[column * 4 + row] = S[row][column];
		}
	}
}

void MyAES::GenerateRandom128(uint8_t(&oData128)[16])
{
	time_t t;
	srand(time(&t));
	for (size_t i = 0; i < 16; i++)
	{
		oData128[i] = rand();
	}
}

void MyAES::XOR128(uint8_t(&a128)[16], uint8_t b128[16])
{
	for (size_t i = 0; i < 16; i++)
	{
		a128[i] = a128[i] ^ b128[i];
	}
}

const uint8_t MyAES::S[16][16]= {
	{0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76},
	{0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0},
	{0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15},
	{0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75},
	{0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84},
	{0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF},
	{0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8},
	{0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2},
	{0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73},
	{0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB},
	{0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79},
	{0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08},
	{0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A},
	{0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E},
	{0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF},
	{0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16}
};

const uint8_t MyAES::iS[16][16]= {
	{0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB},
	{0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB},
	{0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E},
	{0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25},
	{0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92},
	{0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84},
	{0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06},
	{0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B},
	{0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73},
	{0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E},
	{0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B},
	{0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4},
	{0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F},
	{0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF},
	{0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61},
	{0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D}
};