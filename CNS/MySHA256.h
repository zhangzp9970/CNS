#pragma once
#include "pch.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

class MySHA256
{
public:
	MySHA256();
	~MySHA256();
	IBuffer SHA256(const IBuffer& data);
private:
	static const uint32_t K[64];
	uint32_t ROTR(uint32_t data, uint8_t bits);
	uint32_t SIGMA0(uint32_t data);
	uint32_t SIGMA1(uint32_t data);
	uint32_t Ch(uint32_t e, uint32_t f, uint32_t g);
	uint32_t Maj(uint32_t a, uint32_t b, uint32_t c);
	uint32_t SUM0(uint32_t a);
	uint32_t SUM1(uint32_t e);
	void SHA256StepFun(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t& e, uint32_t& f, uint32_t& g, uint32_t& h, uint32_t w, uint32_t k);
	IBuffer CreateBufferSHA256(uint32_t h00, uint32_t h01, uint32_t h02, uint32_t h03, uint32_t h04, uint32_t h05, uint32_t h06, uint32_t h07);
};

