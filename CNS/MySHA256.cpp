#include "pch.h"
#include "MySHA256.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

MySHA256::MySHA256()
{
}

MySHA256::~MySHA256()
{
}

IBuffer MySHA256::SHA256(const IBuffer& data)
{
	const double SHA256MAXINPUTBYTE = pow(2, 61);//2^64 bits
	const int SHA256OUTPUTBYTE = 32;//256 bits
	const int SHA256BATCHBYTE = 64;//512 bits
	const int SHA256MODBYTE = 56;//448 bits
	const int SHA256TOTALROUND = 64;//64 rounds
	const int SHA256SUBBATCHBYTE = 4;//32 bits
	uint8_t FirstByte = 128;//0x80
	uint8_t ZeroByte = 0;//0x00
	uint32_t H00 = 0x6A09E667;
	uint32_t H01 = 0xBB67AE85;
	uint32_t H02 = 0x3C6EF372;
	uint32_t H03 = 0xA54FF53A;
	uint32_t H04 = 0x510E527F;
	uint32_t H05 = 0x9B05688C;
	uint32_t H06 = 0x1F83D9AB;
	uint32_t H07 = 0x5BE0CD19;
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t F;
	uint32_t G;
	uint32_t H;
	uint32_t W[64];
	uint64_t OriginalDataLength = data.Length();
	uint64_t batches = 0;
	uint64_t TotalDataLength = 0;
	InMemoryRandomAccessStream stream;
	DataWriter dw(stream);
	dw.UnicodeEncoding(UnicodeEncoding::Utf8);
	dw.ByteOrder(ByteOrder::BigEndian);
	DataReader dr(stream);
	dr.UnicodeEncoding(UnicodeEncoding::Utf8);
	dr.ByteOrder(ByteOrder::BigEndian);
	if (OriginalDataLength > SHA256MAXINPUTBYTE)//error when extends 2^64 bit
	{
		throw hresult_error();
	}
	dw.WriteBuffer(data);
	//padding
	int BytestoAppend = SHA256MODBYTE - (OriginalDataLength % SHA256BATCHBYTE);
	if (BytestoAppend == 0)
	{
		BytestoAppend = 64;
	}
	dw.WriteByte(FirstByte);
	for (size_t i = 1; i < BytestoAppend; i++)
	{
		dw.WriteByte(ZeroByte);
	}
	dw.WriteUInt64(OriginalDataLength << 3);
	dw.StoreAsync();//put data into stream
	dw.DetachStream();
	//group
	TotalDataLength = stream.Size();
	batches = TotalDataLength / SHA256BATCHBYTE;
	stream.Seek(0);//put pointer to start
	dr.LoadAsync(uint32_t(TotalDataLength));
	for (size_t batch = 0; batch < batches; batch++)//N groups
	{
		//make W[]
		for (size_t i = 0; i < 16; i++)//first 16 words
		{
			W[i] = dr.ReadUInt32();
		}
		for (size_t i = 16; i < 64; i++)//other words
		{
			W[i] = W[i - 16] + SIGMA0(W[i - 15]) + W[i - 7] + SIGMA1(W[i - 2]);
		}
		//assign A,B,C,D,E,F,G and H
		A = H00;
		B = H01;
		C = H02;
		D = H03;
		E = H04;
		F = H05;
		G = H06;
		H = H07;
		//compute SHA
		for (size_t round = 0; round < SHA256TOTALROUND; round++)
		{
			SHA256StepFun(A, B, C, D, E, F, G, H, W[round], K[round]);
		}
		//module add
		H00 += A;
		H01 += B;
		H02 += C;
		H03 += D;
		H04 += E;
		H05 += F;
		H06 += G;
		H07 += H;
	}
	return CreateBufferSHA256(H00, H01, H02, H03, H04, H05, H06, H07);
}

uint32_t MySHA256::ROTR(uint32_t data, uint8_t bits)
{
	return (data << (32 - bits)) | (data >> bits);
}

uint32_t MySHA256::SIGMA0(uint32_t data)
{
	return ROTR(data, 7) ^ ROTR(data, 18) ^ (data >> 3);
}

uint32_t MySHA256::SIGMA1(uint32_t data)
{
	return ROTR(data, 17) ^ ROTR(data, 19) ^ (data >> 10);
}

uint32_t MySHA256::Ch(uint32_t e, uint32_t f, uint32_t g)
{
	return (e & f) ^ (~e & g);
}

uint32_t MySHA256::Maj(uint32_t a, uint32_t b, uint32_t c)
{
	return (a & b) ^ (a & c) ^ (b & c);
}

uint32_t MySHA256::SUM0(uint32_t a)
{
	return ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
}

uint32_t MySHA256::SUM1(uint32_t e)
{
	return ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
}

void MySHA256::SHA256StepFun(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t& e, uint32_t& f, uint32_t& g, uint32_t& h, uint32_t w, uint32_t k)
{
	uint32_t T1 = SUM1(e) + Ch(e, f, g) + h + w + k;
	uint32_t T2 = SUM0(a) + Maj(a, b, c);
	h = g;
	g = f;
	f = e;
	e = d + T1;
	d = c;
	c = b;
	b = a;
	a = T1 + T2;
}

IBuffer MySHA256::CreateBufferSHA256(uint32_t h00, uint32_t h01, uint32_t h02, uint32_t h03, uint32_t h04, uint32_t h05, uint32_t h06, uint32_t h07)
{
	uint8_t buffer[32];
	for (size_t i = 0; i < 4; i++)
	{
		buffer[3 - i] = h00 >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[7 - i] = h01 >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[11 - i] = h02 >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[15 - i] = h03 >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[19 - i] = h04 >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[23 - i] = h05 >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[27 - i] = h06 >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[31 - i] = h07 >> (i * 8);
	}
	return CryptographicBuffer::CreateFromByteArray(buffer);
}

const uint32_t MySHA256::K[64] = {
	0x428A2F98,//K[0]
	0x71374491,//K[1]
	0xB5C0FBCF,//K[2]
	0xE9B5DBA5,//K[3]
	0x3956C25B,//K[4]
	0x59F111F1,//K[5]
	0x923F82A4,//K[6]
	0xAB1C5ED5,//K[7]
	0xD807AA98,//K[8]
	0x12835B01,//K[9]
	0x243185BE,//K[10]
	0x550C7DC3,//K[11]
	0x72BE5D74,//K[12]
	0x80DEB1FE,//K[13]
	0x9BDC06A7,//K[14]
	0xC19BF174,//K[15]
	0xE49B69C1,//K[16]
	0xEFBE4786,//K[17]
	0x0FC19DC6,//K[18]
	0x240CA1CC,//K[19]
	0x2DE92C6F,//K[20]
	0x4A7484AA,//K[21]
	0x5CB0A9DC,//K[22]
	0x76F988DA,//K[23]
	0x983E5152,//K[24]
	0xA831C66D,//K[25]
	0xB00327C8,//K[26]
	0xBF597FC7,//K[27]
	0xC6E00BF3,//K[28]
	0xD5A79147,//K[29]
	0x06CA6351,//K[30]
	0x14292967,//K[31]
	0x27B70A85,//K[32]
	0x2E1B2138,//K[33]
	0x4D2C6DFC,//K[34]
	0x53380D13,//K[35]
	0x650A7354,//K[36]
	0x766A0ABB,//K[37]
	0x81C2C92E,//K[38]
	0x92722C85,//K[39]
	0xA2BFE8A1,//K[40]
	0xA81A664B,//K[41]
	0xC24B8B70,//K[42]
	0xC76C51A3,//K[43]
	0xD192E819,//K[44]
	0xD6990624,//K[45]
	0xF40E3585,//K[46]
	0x106AA070,//K[47]
	0x19A4C116,//K[48]
	0x1E376C08,//K[49]
	0x2748774C,//K[50]
	0x34B0BCB5,//K[51]
	0x391C0CB3,//K[52]
	0x4ED8AA4A,//K[53]
	0x5B9CCA4F,//K[54]
	0x682E6FF3,//K[55]
	0x748F82EE,//K[56]
	0x78A5636F,//K[57]
	0x84C87814,//K[58]
	0x8CC70208,//K[59]
	0x90BEFFFA,//K[60]
	0xA4506CEB,//K[61]
	0xBEF9A3F7,//K[62]
	0xC67178F2 //K[63]
};