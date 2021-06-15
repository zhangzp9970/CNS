#include "pch.h"
#include "BigInteger.h"
#include "RSA.h"
#include "MyRSA.h"

using namespace std;
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

MyRSA::MyRSA()
{
}

MyRSA::~MyRSA()
{
}

void MyRSA::InitRSA()
{
	RSACore.init(200 >> 1);
}

hstring MyRSA::Encrypt(const hstring& iData)
{
	BigInteger m(to_string(iData));
	BigInteger c = RSACore.encryptByPublic(m);
	return to_hstring(c.toString());
}

hstring MyRSA::Decrypt(const hstring& iData)
{
	BigInteger c(to_string(iData));
	BigInteger m = RSACore.decryptByPrivate(c);
	return to_hstring(m.toString());
}

hstring MyRSA::Sign(const hstring& iData)
{
	BigInteger hm(to_string(iData));
	BigInteger s = RSACore.encryptByPrivate(hm);
	return to_hstring(s.toString());
}

bool MyRSA::Verify(const hstring& iData, const hstring& hm)
{
	BigInteger hm1(to_string(hm));
	BigInteger s(to_string(iData));
	BigInteger hm2 = RSACore.decryptByPublic(s);
	if (hm1.mod(RSACore.n)== hm2.mod(RSACore.n))
	{
		return true;
	}
	else
	{
		return false;
	}
}
