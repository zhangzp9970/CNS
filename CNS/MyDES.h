#pragma once
#include "pch.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

class MyDES
{
public:
	MyDES();
	~MyDES();
	hstring Key();
	void Key(hstring& iData);
	hstring IV();
	void IV(hstring& iData);
	void GenerateSymmetricKey64();
	void GenerateSymmetricKey64(const hstring key);
	hstring DESCBC(const IBuffer& iData, bool encrypt);

private:
	static const uint8_t PC1[56];
	static const uint8_t PC2[48];
	static const uint8_t IP[64];
	static const uint8_t IP_1[64];
	static const uint8_t E[48];
	static const uint8_t S1[4][16];
	static const uint8_t S2[4][16];
	static const uint8_t S3[4][16];
	static const uint8_t S4[4][16];
	static const uint8_t S5[4][16];
	static const uint8_t S6[4][16];
	static const uint8_t S7[4][16];
	static const uint8_t S8[4][16];
	static const uint8_t P[32];
	uint8_t Key64[8] = { 0,0,0,0,0,0,0,0 };
	uint8_t IV64[8] = { 0,0,0,0,0,0,0,0 };
	void CopyBit8(uint8_t SourceByte, uint8_t& DestinationByte, uint8_t sBit, uint8_t dBit);
	void PerformPC1(uint8_t key64[8], uint8_t(&key56)[7]);
	void DESKEY56ROL(uint8_t(&key56)[7], uint8_t bits);
	void PerformPC2(uint8_t key56[7], uint8_t(&key48)[6]);
	void DESSubKeyGenerator(uint8_t key64[8], uint8_t(&key48)[16][6]);
	void PerformIP(uint8_t iData64[8], uint8_t(&oData64)[8]);
	void PerformIP_1(uint8_t iData64[8], uint8_t(&oData64)[8]);
	void PerformE(uint8_t iData32[4], uint8_t(&oData48)[6]);
	void XOR48(uint8_t(&a48)[6], uint8_t b48[6]);
	void XOR32(uint8_t(&a32)[4], uint8_t b32[4]);
	void XOR64(uint8_t(&a64)[8], uint8_t b64[8]);
	void PerformSbox(uint8_t iData48[6], uint8_t(&oData32)[4]);
	void PerformP(uint8_t iData32[4], uint8_t(&oData32)[4]);
	void F(uint8_t(&r32)[4], uint8_t K48[6]);
	void DES(uint8_t iData64[8], uint8_t(&oData64)[8], uint8_t key64[8], bool encrypt);
	void GenerateRandom64(uint8_t(&oData64)[8]);
};

