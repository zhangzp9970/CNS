#pragma once
#include "pch.h"
#include "BigInteger.h"
#include "RSA.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

class MyRSA
{
public:
	MyRSA();
	~MyRSA();
	void InitRSA();
	hstring Encrypt(const hstring& iData);
	hstring Decrypt(const hstring& iData);
	hstring Sign(const hstring& iData);
	bool Verify(const hstring& iData, const hstring &hm);
	//BigInteger n, e;
private:
	//BigInteger d;
	//BigInteger p, q;
	//BigInteger eul;
	RSA RSACore;
};

