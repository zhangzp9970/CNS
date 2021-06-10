#include "pch.h"
#include "MyMD5.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

MyMD5::MyMD5()
{
}

MyMD5::~MyMD5()
{
}

IBuffer MyMD5::MD5(const IBuffer& data)
{
    const double MD5MAXINPUTBYTE = pow(2, 61);//2^64 bits
    const int MD5OUTPUTBYTE = 16;//128 bits
    const int MD5BATCHBYTE = 64;//512 bits
    const int MD5MODBYTE = 56;//448 bits
    const int MD5TOTALROUND = 4;//4 rounds
    const int MD5SUBBATCHBYTE = 4;//32 bits
    const int MD5SUBBATCHNUM = 16;//16 sub batches
    const int MD5STEPPROUND = 16;//16 step per round
    uint8_t FirstByte = 128;//0x80
    uint8_t ZeroByte = 0;//0x00
    uint32_t A = 0x01234567;//0x01234567
    uint32_t B = 0x89ABCDEF;//0x89ABCDEF
    uint32_t C = 0xFEDCBA98;//0xFEDCBA98
    uint32_t D = 0x76543210;//0x76543210
    uint32_t AA;//for backup
    uint32_t BB;
    uint32_t CC;
    uint32_t DD;
    uint32_t M[16] = { 0 };
    uint64_t OriginalDataLength = data.Length();
    uint64_t batches = 0;
    uint64_t TotalDataLength = 0;
    InMemoryRandomAccessStream stream;
    DataWriter dw(stream);
    dw.UnicodeEncoding(UnicodeEncoding::Utf8);
    dw.ByteOrder(ByteOrder::LittleEndian);
    DataReader dr(stream);
    dr.UnicodeEncoding(UnicodeEncoding::Utf8);
    dr.ByteOrder(ByteOrder::LittleEndian);
    if (OriginalDataLength > MD5MAXINPUTBYTE)//error when extends 2^64 bit
    {
        throw hresult_error();
    }
    dw.WriteBuffer(data);
    //padding
    int BytestoAppend = MD5MODBYTE - (OriginalDataLength % MD5BATCHBYTE);
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
    batches = TotalDataLength / MD5BATCHBYTE;
    stream.Seek(0);//put pointer to start
    dr.LoadAsync(uint32_t(TotalDataLength));
    //change small endian to big endian
    SwapEndianABCD(A, B, C, D);
    for (size_t batch = 0; batch < batches; batch++)//N groups
    {
        //backup the A, B, C, D
        AA = A;
        BB = B;
        CC = C;
        DD = D;
        //make M[]
        for (size_t i = 0; i < MD5SUBBATCHNUM; i++)
        {
            M[i] = dr.ReadUInt32();
        }
        //run compress function
        FF(A, B, C, D, M[0], s1[0], 1);
        FF(A, B, C, D, M[1], s1[1], 2);
        FF(A, B, C, D, M[2], s1[2], 3);
        FF(A, B, C, D, M[3], s1[3], 4);
        FF(A, B, C, D, M[4], s1[0], 5);
        FF(A, B, C, D, M[5], s1[1], 6);
        FF(A, B, C, D, M[6], s1[2], 7);
        FF(A, B, C, D, M[7], s1[3], 8);
        FF(A, B, C, D, M[8], s1[0], 9);
        FF(A, B, C, D, M[9], s1[1], 10);
        FF(A, B, C, D, M[10], s1[2], 11);
        FF(A, B, C, D, M[11], s1[3], 12);
        FF(A, B, C, D, M[12], s1[0], 13);
        FF(A, B, C, D, M[13], s1[1], 14);
        FF(A, B, C, D, M[14], s1[2], 15);
        FF(A, B, C, D, M[15], s1[3], 16);
        GG(A, B, C, D, M[1], s2[0], 17);
        GG(A, B, C, D, M[6], s2[1], 18);
        GG(A, B, C, D, M[11], s2[2], 19);
        GG(A, B, C, D, M[0], s2[3], 20);
        GG(A, B, C, D, M[5], s2[0], 21);
        GG(A, B, C, D, M[10], s2[1], 22);
        GG(A, B, C, D, M[15], s2[2], 23);
        GG(A, B, C, D, M[4], s2[3], 24);
        GG(A, B, C, D, M[9], s2[0], 25);
        GG(A, B, C, D, M[14], s2[1], 26);
        GG(A, B, C, D, M[3], s2[2], 27);
        GG(A, B, C, D, M[8], s2[3], 28);
        GG(A, B, C, D, M[13], s2[0], 29);
        GG(A, B, C, D, M[2], s2[1], 30);
        GG(A, B, C, D, M[7], s2[2], 31);
        GG(A, B, C, D, M[12], s2[3], 32);
        HH(A, B, C, D, M[5], s3[0], 33);
        HH(A, B, C, D, M[8], s3[1], 34);
        HH(A, B, C, D, M[11], s3[2], 35);
        HH(A, B, C, D, M[14], s3[3], 36);
        HH(A, B, C, D, M[1], s3[0], 37);
        HH(A, B, C, D, M[4], s3[1], 38);
        HH(A, B, C, D, M[7], s3[2], 39);
        HH(A, B, C, D, M[10], s3[3], 40);
        HH(A, B, C, D, M[13], s3[0], 41);
        HH(A, B, C, D, M[0], s3[1], 42);
        HH(A, B, C, D, M[3], s3[2], 43);
        HH(A, B, C, D, M[6], s3[3], 44);
        HH(A, B, C, D, M[9], s3[0], 45);
        HH(A, B, C, D, M[12], s3[1], 46);
        HH(A, B, C, D, M[15], s3[2], 47);
        HH(A, B, C, D, M[2], s3[3], 48);
        II(A, B, C, D, M[0], s4[0], 49);
        II(A, B, C, D, M[7], s4[1], 50);
        II(A, B, C, D, M[14], s4[2], 51);
        II(A, B, C, D, M[5], s4[3], 52);
        II(A, B, C, D, M[12], s4[0], 53);
        II(A, B, C, D, M[3], s4[1], 54);
        II(A, B, C, D, M[10], s4[2], 55);
        II(A, B, C, D, M[1], s4[3], 56);
        II(A, B, C, D, M[8], s4[0], 57);
        II(A, B, C, D, M[15], s4[1], 58);
        II(A, B, C, D, M[6], s4[2], 59);
        II(A, B, C, D, M[13], s4[3], 60);
        II(A, B, C, D, M[4], s4[0], 61);
        II(A, B, C, D, M[11], s4[1], 62);
        II(A, B, C, D, M[2], s4[2], 63);
        II(A, B, C, D, M[9], s4[3], 64);
        //module addition as the last step
        A += AA;
        B += BB;
        C += CC;
        D += DD;
    }
    //swap endian again
    SwapEndianABCD(A, B, C, D);
    return CreateIBufferABCD(A, B, C, D);
}

void MyMD5::SwapEndian(uint32_t& x)
{
	x = (x >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | (x << 24);
}

void MyMD5::SwapEndianABCD(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
	SwapEndian(a);
	SwapEndian(b);
	SwapEndian(c);
	SwapEndian(d);
}

uint32_t MyMD5::F(uint32_t X, uint32_t Y, uint32_t Z)
{
	return (X & Y) | (~X & Z);
}

uint32_t MyMD5::G(uint32_t X, uint32_t Y, uint32_t Z)
{
	return (X & Z) | (Y & ~Z);
}

uint32_t MyMD5::H(uint32_t X, uint32_t Y, uint32_t Z)
{
	return X ^ Y ^ Z;
}

uint32_t MyMD5::I(uint32_t X, uint32_t Y, uint32_t Z)
{
	return Y ^ (X | ~Z);
}

uint32_t MyMD5::ROL(uint32_t data, uint8_t bits)
{
	return (data >> (32 - bits)) | (data << bits);
}

void MyMD5::ExchangeABCD(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
	uint32_t temp = 0;
	temp = d;
	d = c;
	c = b;
	b = a;
	a = temp;
}

void MyMD5::FF(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti)
{
	a += F(b, c, d);
	a += M;
	a += T[Ti - 1];
	a = ROL(a, s);
	a += b;
	ExchangeABCD(a, b, c, d);
}

void MyMD5::GG(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti)
{
	a += G(b, c, d);
	a += M;
	a += T[Ti - 1];
	a = ROL(a, s);
	a += b;
	ExchangeABCD(a, b, c, d);
}

void MyMD5::HH(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti)
{
	a += H(b, c, d);
	a += M;
	a += T[Ti - 1];
	a = ROL(a, s);
	a += b;
	ExchangeABCD(a, b, c, d);
}

void MyMD5::II(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t M, uint8_t s, uint8_t Ti)
{
	a += I(b, c, d);
	a += M;
	a += T[Ti - 1];
	a = ROL(a, s);
	a += b;
	ExchangeABCD(a, b, c, d);
}

IBuffer MyMD5::CreateIBufferABCD(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	uint8_t buffer[16];
	for (size_t i = 0; i < 4; i++)
	{
		buffer[3 - i] = a >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[7 - i] = b >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[11 - i] = c >> (i * 8);
	}
	for (size_t i = 0; i < 4; i++)
	{
		buffer[15 - i] = d >> (i * 8);
	}
	return CryptographicBuffer::CreateFromByteArray(buffer);
}

const uint32_t MyMD5::T[64] = {
	0xD76AA478,//T[1]
	0xE8C7B756,//T[2]
	0x242070DB,//T[3]
	0xC1BDCEEE,//T[4]
	0xF57C0FAF,//T[5]
	0x4787C62A,//T[6]
	0xA8304613,//T[7]
	0xFD469501,//T[8]
	0x698098D8,//T[9]
	0x8B44F7AF,//T[10]
	0xFFFF5BB1,//T[11]
	0x895CD7BE,//T[12]
	0x6B901122,//T[13]
	0xFD987193,//T[14]
	0xA679438E,//T[15]
	0x49B40821,//T[16]
	0xF61E2562,//T[17]
	0xC040B340,//T[18]
	0x265E5A51,//T[19]
	0xE9B6C7AA,//T[20]
	0xD62F105D,//T[21]
	0x02441453,//T[22]
	0xD8A1E681,//T[23]
	0xE7D3FBC8,//T[24]
	0x21E1CDE6,//T[25]
	0xC33707D6,//T[26]
	0xF4D50D87,//T[27]
	0x455A14ED,//T[28]
	0xA9E3E905,//T[29]
	0xFCEFA3F8,//T[30]
	0x676F02D9,//T[31]
	0x8D2A4C8A,//T[32]
	0xFFFA3942,//T[33]
	0x8771F681,//T[34]
	0x6D9D6122,//T[35]
	0xFDE5380C,//T[36]
	0xA4BEEA44,//T[37]
	0x4BDECFA9,//T[38]
	0xF6BB4B60,//T[39]
	0xBEBFBC70,//T[40]
	0x289B7EC6,//T[41]
	0xEAA127FA,//T[42]
	0xD4EF3085,//T[43]
	0x04881D05,//T[44]
	0xD9D4D039,//T[45]
	0xE6DB99E5,//T[46]
	0x1FA27CF8,//T[47]
	0xC4AC5665,//T[48]
	0xF4292244,//T[49]
	0x432AFF97,//T[50]
	0xAB9423A7,//T[51]
	0xFC93A039,//T[52]
	0x655B59C3,//T[53]
	0x8F0CCC92,//T[54]
	0xFFEFF47D,//T[55]
	0x85845DD1,//T[56]
	0x6FA87E4F,//T[57]
	0xFE2CE6E0,//T[58]
	0xA3014314,//T[59]
	0x4E0811A1,//T[60]
	0xF7537E82,//T[61]
	0xBD3AF235,//T[62]
	0x2AD7D2BB,//T[63]
	0xEB86D391 //T[64]
};

const uint8_t MyMD5::s1[4] = { 7,12,17,22 };
const uint8_t MyMD5::s2[4] = { 5,9,14,20 };
const uint8_t MyMD5::s3[4] = { 4,11,16,23 };
const uint8_t MyMD5::s4[4] = { 6,10,15,21 };