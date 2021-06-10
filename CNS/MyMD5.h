#pragma once
#include "pch.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

class MyMD5
{
public:
	MyMD5();
	~MyMD5();
	IBuffer MD5(const IBuffer& data);

private:
	static const uint32_t T[64];
	static const uint8_t s1[4];
	static const uint8_t s2[4];
	static const uint8_t s3[4];
	static const uint8_t s4[4];
	void SwapEndian(uint32_t& x);
	void SwapEndianABCD(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
	uint32_t F(uint32_t X, uint32_t Y, uint32_t Z);
	uint32_t G(uint32_t X, uint32_t Y, uint32_t Z);
	uint32_t H(uint32_t X, uint32_t Y, uint32_t Z);
	uint32_t I(uint32_t X, uint32_t Y, uint32_t Z);
	uint32_t ROL(uint32_t data, uint8_t bits);
	void ExchangeABCD(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
	void FF(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti);
	void GG(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti);
	void HH(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti);
	void II(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti);
	IBuffer CreateIBufferABCD(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
};

