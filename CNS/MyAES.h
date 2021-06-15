#pragma once
#include "pch.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

class MyAES
{
public:
	MyAES();
	~MyAES();
	hstring Key();
	void Key(hstring& iData);
	hstring IV();
	void IV(hstring& iData);
	void GenerateSymmetricKey128();
	void GenerateSymmetricKey128(const hstring key);
	hstring AESCBC(const IBuffer& iData, bool encrypt);

private:
	static const uint8_t S[16][16];
	static const uint8_t iS[16][16];
	uint8_t Key128[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t IV128[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t PerformSbox(uint8_t iByte);
	uint8_t PerformiSbox(uint8_t iByte);
	uint32_t T(uint32_t w, uint8_t round);
	void KeyExpansion(const uint8_t(&K)[4][4], uint32_t(&w)[44]);
	void RoundKeyAdd(uint32_t(&w)[4], uint8_t(&s)[4][4]);
	uint8_t Multi2GF2_8(uint8_t iData);
	uint8_t Multi3GF2_8(uint8_t iData);
	uint8_t Multi9GF2_8(uint8_t iData);
	uint8_t MultiBGF2_8(uint8_t iData);
	uint8_t MultiDGF2_8(uint8_t iData);
	uint8_t MultiEGF2_8(uint8_t iData);
	void ColumnMixture(uint8_t(&S)[4][4]);
	void iColumnMixture(uint8_t(&S)[4][4]);
	void AES128Encrypt(uint8_t iData128[16], uint8_t(&oData128)[16], uint8_t key128[16]);
	void AES128Decrypt(uint8_t iData128[16], uint8_t(&oData128)[16], uint8_t key128[16]);
	void GenerateRandom128(uint8_t(&oData128)[16]);
	void XOR128(uint8_t(&a128)[16], uint8_t b128[16]);
};

