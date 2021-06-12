#include "pch.h"
#include "MyDES.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

MyDES::MyDES()
{
}

MyDES::~MyDES()
{
}

void MyDES::GenerateSymmetricKey64()
{
	GenerateRandom64(this->Key64);
}

void MyDES::GenerateSymmetricKey64(const hstring key)
{
	int i = 0;
	for each (uint8_t item in to_string(key))
	{
		Key64[i++] = item;
	}
}

hstring MyDES::DESCBC(const IBuffer& data, bool encrypt)
{
	hstring oText = L"";
	//uint8_t key[8] = { 0,1,2,3,4,5,6,7 };
	uint8_t iBlock64[8] = { 0,0,0,0,0,0,0,0 };
	uint8_t oBlock64[8] = { 0,0,0,0,0,0,0,0 };
	uint8_t IV[8] = { 0,0,0,0,0,0,0,0 };
	DataReader dr = DataReader::FromBuffer(data);
	if (encrypt)
	{
		GenerateRandom64(this->IV64);
	}
	for (size_t i = 0; i < 8; i++)
	{
		IV[i] = IV64[i];
	}
	while (dr.UnconsumedBufferLength()>0)
	{
		uint32_t UCBL = dr.UnconsumedBufferLength();
		for (size_t i = 0; i < min(8u, UCBL); i++)
		{
			iBlock64[i] = dr.ReadByte();
		}
		if (encrypt)//encrypt
		{
			XOR64(IV, iBlock64);
			DES(IV, IV, this->Key64,encrypt);
			oText = oText + CryptographicBuffer::EncodeToHexString(CryptographicBuffer::CreateFromByteArray(IV));
		}
		else
		{
			DES(iBlock64, oBlock64, this->Key64, encrypt);
			XOR64(oBlock64, IV);
			for (size_t i = 0; i < 8; i++)
			{
				IV[i] = iBlock64[i];
			}
			oText = oText + CryptographicBuffer::ConvertBinaryToString(BinaryStringEncoding::Utf8, CryptographicBuffer::CreateFromByteArray(oBlock64));
		}
	}
	return oText;
}

void MyDES::CopyBit8(uint8_t SourceByte, uint8_t& DestinationByte, uint8_t sBit, uint8_t dBit)
{
	uint8_t sampler1 = 0x80;
	uint8_t sampler2 = 0x80;
	sampler1 = sampler1 >> sBit;
	sampler2 = sampler2 >> dBit;
	sampler1 = sampler1 & SourceByte;
	sampler2 = sampler2 & DestinationByte;
	sampler1 = sampler1 << sBit;
	sampler2 = sampler2 << dBit;
	if ((sampler1 == 0x80) && (sampler2 == 0x00))
	{
		sampler1 = sampler1 >> dBit;
		DestinationByte = DestinationByte ^ sampler1;
	}
	else if ((sampler1 == 0x00) && (sampler2 == 0x80))
	{
		sampler2 = sampler2 >> dBit;
		DestinationByte = DestinationByte ^ sampler2;
	}
	else
	{
		//do nothing
	}
}

void MyDES::PerformPC1(uint8_t key64[8], uint8_t(&key56)[7])
{
	for (size_t i = 0; i < 56; i++)
	{
		CopyBit8(key64[(PC1[i] - 1) / 8], key56[i / 8], (PC1[i] - 1) % 8, i % 8);
	}
}

void MyDES::DESKEY56ROL(uint8_t(&key56)[7], uint8_t bits)
{
	uint8_t temp = key56[0];
	for (size_t i = 0; i < 6; i++)
	{
		key56[i] = (key56[i] << bits) | (key56[i + 1] >> (8 - bits));
	}
	key56[6] = (key56[6] << bits) | (temp >> (8 - bits));
	if (bits == 1)
	{
		uint8_t temp = key56[6];
		CopyBit8(key56[3], key56[6], 3, 7);
		CopyBit8(temp, key56[3], 7, 3);
	}
	else if (bits == 2)
	{
		uint8_t temp = key56[6];
		CopyBit8(key56[3], key56[6], 2, 6);
		CopyBit8(key56[3], key56[6], 3, 7);
		CopyBit8(temp, key56[3], 6, 2);
		CopyBit8(temp, key56[3], 7, 3);
	}
}

void MyDES::PerformPC2(uint8_t key56[7], uint8_t(&key48)[6])
{
	for (size_t i = 0; i < 48; i++)
	{
		CopyBit8(key56[(PC2[i] - 1) / 8], key48[i / 8], (PC2[i] - 1) % 8, i % 8);
	}
}

void MyDES::DESSubKeyGenerator(uint8_t key64[8], uint8_t(&key48)[16][6])
{
	uint8_t tempKey56[7] = { 0,0,0,0,0,0,0 };
	//perform PC-1
	PerformPC1(key64, tempKey56);
	//16 rounds to generate 16 subkeys
	for (size_t i = 1; i <= 16; i++)
	{
		if ((i == 1) || (i == 2) || (i == 9) || (i == 16))
		{
			DESKEY56ROL(tempKey56, 1);
		}
		else
		{
			DESKEY56ROL(tempKey56, 2);
		}
		PerformPC2(tempKey56, key48[i - 1]);
	}
}

void MyDES::PerformIP(uint8_t iData64[8], uint8_t(&oData64)[8])
{
	for (size_t i = 0; i < 64; i++)
	{
		CopyBit8(iData64[(IP[i] - 1) / 8], oData64[i / 8], (IP[i] - 1) % 8, i % 8);
	}
}

void MyDES::PerformIP_1(uint8_t iData64[8], uint8_t(&oData64)[8])
{
	for (size_t i = 0; i < 64; i++)
	{
		CopyBit8(iData64[(IP_1[i] - 1) / 8], oData64[i / 8], (IP_1[i] - 1) % 8, i % 8);
	}
}

void MyDES::PerformE(uint8_t iData32[4], uint8_t(&oData48)[6])
{
	for (size_t i = 0; i < 48; i++)
	{
		CopyBit8(iData32[(E[i] - 1) / 8], oData48[i / 8], (E[i] - 1) % 8, i % 8);
	}
}

void MyDES::XOR48(uint8_t(&a48)[6], uint8_t b48[6])
{
	for (size_t i = 0; i < 6; i++)
	{
		a48[i] = a48[i] ^ b48[i];
	}
}

void MyDES::XOR32(uint8_t(&a32)[4], uint8_t b32[4])
{
	for (size_t i = 0; i < 4; i++)
	{
		a32[i] = a32[i] ^ b32[i];
	}
}

void MyDES::XOR64(uint8_t(&a64)[8], uint8_t b64[8])
{
	for (size_t i = 0; i < 8; i++)
	{
		a64[i] = a64[i] ^ b64[i];
	}
}

void MyDES::PerformSbox(uint8_t iData48[6], uint8_t(&oData32)[4])
{
	uint8_t row = 0;
	uint8_t column = 0;
	uint8_t output[8] = { 0,0,0,0,0,0,0,0 };
	uint8_t sampler = 0x80;
	for (size_t i = 0; i < 8; i++)
	{
		CopyBit8(iData48[(i * 6) / 8], row, (i * 6) % 8, 6);
		CopyBit8(iData48[(i * 6 + 5) / 8], row, (i * 6 + 5) % 8, 7);
		CopyBit8(iData48[(i * 6 + 1) / 8], column, (i * 6 + 1) % 8, 4);
		CopyBit8(iData48[(i * 6 + 2) / 8], column, (i * 6 + 2) % 8, 5);
		CopyBit8(iData48[(i * 6 + 3) / 8], column, (i * 6 + 3) % 8, 6);
		CopyBit8(iData48[(i * 6 + 4) / 8], column, (i * 6 + 4) % 8, 7);
		switch (i)
		{
		case 0:
			output[i] = S1[row][column];
			break;
		case 1:
			output[i] = S2[row][column];
			break;
		case 3:
			output[i] = S3[row][column];
			break;
		case 4:
			output[i] = S4[row][column];
			break;
		case 5:
			output[i] = S5[row][column];
			break;
		case 6:
			output[i] = S6[row][column];
			break;
		case 7:
			output[i] = S7[row][column];
			break;
		default:
			break;
		}
	}
	for (size_t i = 0; i < 8; i = i + 2)
	{
		oData32[i / 2] = (output[i] << 4) | (output[i + 1]);
	}
}

void MyDES::PerformP(uint8_t iData32[4], uint8_t(&oData32)[4])
{
	for (size_t i = 0; i < 32; i++)
	{
		CopyBit8(iData32[(P[i] - 1) / 8], oData32[i / 8], (P[i] - 1) % 8, i % 8);
	}
}

void MyDES::F(uint8_t(&r32)[4], uint8_t K48[6])
{
	uint8_t temp48[6] = { 0,0,0,0,0,0 };
	uint8_t temp32[4] = { 0,0,0,0 };
	PerformE(r32, temp48);
	XOR48(temp48, K48);
	PerformSbox(temp48, temp32);
	PerformP(temp32, r32);
}

void MyDES::DES(uint8_t iData64[8], uint8_t(&oData64)[8], uint8_t key64[8], bool encrypt)
{
	uint8_t tData64[8] = { 0,0,0,0,0,0,0,0 };
	uint8_t L32[4] = { 0,0,0,0 };
	uint8_t R32[4] = { 0,0,0,0 };
	uint8_t key48[16][6];
	for (size_t i = 0; i < 15; i++)
	{
		for (size_t j = 0; j < 6; j++)
		{
			key48[i][j] = 0;
		}
	}
	//generate 16 48bit keys
	DESSubKeyGenerator(key64, key48);
	//IP
	PerformIP(iData64, tData64);
	for (size_t i = 0; i < 4; i++)
	{
		L32[i] = tData64[i];
		R32[i] = tData64[i + 4];
	}
	//16 rounds
	for (size_t i = 0; i < 16; i++)
	{
		uint8_t temp32[4] = { 0,0,0,0 };
		for (size_t i = 0; i < 4; i++)//backup R
		{
			temp32[i] = R32[i];
		}
		if (encrypt)//encrypt
		{
			F(R32, key48[i]);
		}
		else
		{
			F(R32, key48[15 - i]);
		}
		XOR32(L32, R32);
		if (i < 15)// exchange L and R during round 1-15
		{
			for (size_t i = 0; i < 4; i++)
			{
				R32[i] = L32[i];
				L32[i] = temp32[i];
			}
		}
		else
		{
			for (size_t i = 0; i < 4; i++)
			{
				R32[i] = temp32[i];
			}
		}
	}
	for (size_t i = 0; i < 4; i++)
	{
		tData64[i] = L32[i];
		tData64[i + 4] = R32[i];
	}
	PerformIP_1(tData64, oData64);
}

void MyDES::GenerateRandom64(uint8_t(&oData64)[8])
{
	time_t t;
	srand(time(&t));
	for (size_t i = 0; i < 8; i++)
	{
		oData64[i] = rand();
	}
}

const uint8_t MyDES::PC1[56] = {
	57, //PC1[0]
	49, //PC1[1]
	41, //PC1[2]
	33, //PC1[3]
	25, //PC1[4]
	17, //PC1[5]
	9,	//PC1[6]
	1,	//PC1[7]
	58, //PC1[8]
	50, //PC1[9]
	42, //PC1[10]
	34, //PC1[11]
	26, //PC1[12]
	18, //PC1[13]
	10, //PC1[14]
	2,	//PC1[15]
	59, //PC1[16]
	51, //PC1[17]
	43, //PC1[18]
	35, //PC1[19]
	27, //PC1[20]
	19, //PC1[21]
	11, //PC1[22]
	3,	//PC1[23]
	60, //PC1[24]
	52, //PC1[25]
	44, //PC1[26]
	36, //PC1[27]
	63, //PC1[28]
	55, //PC1[29]
	47, //PC1[30]
	39, //PC1[31]
	31, //PC1[32]
	23, //PC1[33]
	15, //PC1[34]
	7,	//PC1[35]
	62, //PC1[36]
	54, //PC1[37]
	46, //PC1[38]
	38, //PC1[39]
	30, //PC1[40]
	22, //PC1[41]
	14, //PC1[42]
	6,	//PC1[43]
	61, //PC1[44]
	53, //PC1[45]
	45, //PC1[46]
	37, //PC1[47]
	29, //PC1[48]
	21, //PC1[49]
	13, //PC1[50]
	5,	//PC1[51]
	28, //PC1[52]
	20, //PC1[53]
	12, //PC1[54]
	4	//PC1[55]
};

const uint8_t MyDES::PC2[48] = {
	14, //PC2[0]
	17, //PC2[1]
	11, //PC2[2]
	24, //PC2[3]
	1,	//PC2[4]
	5,	//PC2[5]
	3,	//PC2[6]
	28, //PC2[7]
	15, //PC2[8]
	6,	//PC2[9]
	21, //PC2[10]
	10, //PC2[11]
	23, //PC2[12]
	19, //PC2[13]
	12, //PC2[14]
	4,	//PC2[15]
	26, //PC2[16]
	8,	//PC2[17]
	16, //PC2[18]
	7,	//PC2[19]
	27, //PC2[20]
	20, //PC2[21]
	13, //PC2[22]
	2,	//PC2[23]
	41, //PC2[24]
	52, //PC2[25]
	31, //PC2[26]
	37, //PC2[27]
	47, //PC2[28]
	55, //PC2[29]
	30, //PC2[30]
	40, //PC2[31]
	51, //PC2[32]
	45, //PC2[33]
	33, //PC2[34]
	48, //PC2[35]
	44, //PC2[36]
	49, //PC2[37]
	39, //PC2[38]
	56, //PC2[39]
	34, //PC2[40]
	53, //PC2[41]
	46, //PC2[42]
	42, //PC2[43]
	50, //PC2[44]
	36, //PC2[45]
	29, //PC2[46]
	32	//PC2[47]
};

const uint8_t MyDES::IP[64] = {
	58, //IP[0]
	50, //IP[1]
	42, //IP[2]
	34, //IP[3]
	26, //IP[4]
	18, //IP[5]
	10, //IP[6]
	2,	//IP[7]
	60, //IP[8]
	52, //IP[9]
	44, //IP[10]
	36, //IP[11]
	28, //IP[12]
	20, //IP[13]
	12, //IP[14]
	4,	//IP[15]
	62, //IP[16]
	54, //IP[17]
	46, //IP[18]
	38, //IP[19]
	30, //IP[20]
	22, //IP[21]
	14, //IP[22]
	6,	//IP[23]
	64, //IP[24]
	56, //IP[25]
	48, //IP[26]
	40, //IP[27]
	32, //IP[28]
	24, //IP[29]
	16, //IP[30]
	8,	//IP[31]
	57, //IP[32]
	49, //IP[33]
	41, //IP[34]
	33, //IP[35]
	25, //IP[36]
	17, //IP[37]
	9,	//IP[38]
	1,	//IP[39]
	59, //IP[40]
	51, //IP[41]
	43, //IP[42]
	35, //IP[43]
	27, //IP[44]
	19, //IP[45]
	11, //IP[46]
	3,	//IP[47]
	61, //IP[48]
	53, //IP[49]
	45, //IP[50]
	37, //IP[51]
	29, //IP[52]
	21, //IP[53]
	13, //IP[54]
	5,	//IP[55]
	63, //IP[56]
	55, //IP[57]
	47, //IP[58]
	39, //IP[59]
	31, //IP[60]
	23, //IP[61]
	15, //IP[62]
	7	//IP[63]
};

const uint8_t MyDES::IP_1[64] = {
	40, //IP_1[0]
	8,	//IP_1[1]
	48, //IP_1[2]
	16, //IP_1[3]
	56, //IP_1[4]
	24, //IP_1[5]
	64, //IP_1[6]
	32, //IP_1[7]
	39, //IP_1[8]
	7,	//IP_1[9]
	47, //IP_1[10]
	15, //IP_1[11]
	55, //IP_1[12]
	23, //IP_1[13]
	63, //IP_1[14]
	31, //IP_1[15]
	38, //IP_1[16]
	6,	//IP_1[17]
	46, //IP_1[18]
	14, //IP_1[19]
	54, //IP_1[20]
	22, //IP_1[21]
	62, //IP_1[22]
	30, //IP_1[23]
	37, //IP_1[24]
	5,	//IP_1[25]
	45, //IP_1[26]
	13, //IP_1[27]
	53, //IP_1[28]
	21, //IP_1[29]
	61, //IP_1[30]
	29, //IP_1[31]
	36, //IP_1[32]
	4,	//IP_1[33]
	44, //IP_1[34]
	12, //IP_1[35]
	52, //IP_1[36]
	20, //IP_1[37]
	60, //IP_1[38]
	28, //IP_1[39]
	35, //IP_1[40]
	3,	//IP_1[41]
	43, //IP_1[42]
	11, //IP_1[43]
	51, //IP_1[44]
	19, //IP_1[45]
	59, //IP_1[46]
	27, //IP_1[47]
	34, //IP_1[48]
	2,	//IP_1[49]
	42, //IP_1[50]
	10, //IP_1[51]
	50, //IP_1[52]
	18, //IP_1[53]
	58, //IP_1[54]
	26, //IP_1[55]
	33, //IP_1[56]
	1,	//IP_1[57]
	41, //IP_1[58]
	9,	//IP_1[59]
	49, //IP_1[60]
	17, //IP_1[61]
	57, //IP_1[62]
	25	//IP_1[63]
};

const uint8_t MyDES::E[48] = {
	32,
	1,
	2,
	3,
	4,
	5,
	4,
	5,
	6,
	7,
	8,
	9,
	8,
	9,
	10,
	11,
	12,
	13,
	12,
	13,
	14,
	15,
	16,
	17,
	16,
	17,
	18,
	19,
	20,
	21,
	20,
	21,
	22,
	23,
	24,
	25,
	24,
	25,
	26,
	27,
	28,
	29,
	28,
	29,
	30,
	31,
	32,
	1
};

const uint8_t MyDES::S1[4][16] = {
	{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
	{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
	{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
	{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
};

const uint8_t MyDES::S2[4][16] = {
	{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
	{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
	{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
	{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
};

const uint8_t MyDES::S3[4][16] = {
	{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
	{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
	{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
	{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
};

const uint8_t MyDES::S4[4][16] = {
	{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
	{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
	{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
	{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
};

const uint8_t MyDES::S5[4][16] = {
	{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
	{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
	{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
	{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
};

const uint8_t MyDES::S6[4][16] = {
	{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
	{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
	{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
	{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
};

const uint8_t MyDES::S7[4][16] = {
	{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
	{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
	{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
	{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
};

const uint8_t MyDES::S8[4][16] = {
	{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
	{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
	{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
	{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
};

const uint8_t MyDES::P[32] = {
	16,
	7,
	20,
	21,
	29,
	12,
	28,
	17,
	1,
	15,
	18,
	31,
	10,
	2,
	8,
	24,
	14,
	32,
	27,
	3,
	9,
	19,
	13,
	30,
	6,
	22,
	11,
	4,
	25
};