#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#define CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS
#include <string>
#include <tuple>
#include <algorithm>
#include <map>
#include <sstream>
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <vector>
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"Bcrypt.lib")
#pragma comment(lib,"Ncrypt.lib")
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#include <asn_application.h>
#include <asn_internal.h>

#include "AdES.hpp"

#include "TestTest.h"
#include "SigningCertificateV2.h"
#include "SignaturePolicyIdentifier.h"
#include "CommitmentTypeIndication.h"
#include "CompleteCertificateRefs.h"
#include "CompleteRevocationRefs.h"

//using namespace std;

#include "xml\\xml3all.h"

template <typename T = char, typename T2 = std::vector<T>>
inline bool PutFile(const wchar_t* f, T2& d)
{
	HANDLE hX = CreateFile(f, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (hX == INVALID_HANDLE_VALUE)
		return false;
	DWORD A = 0;
	WriteFile(hX, d.data(), (DWORD)d.size(), &A, 0);
	CloseHandle(hX);
	if (A != d.size())
		return false;
	return true;
}

template <typename T = char>
inline bool LoadFile(const wchar_t* f, std::vector<T>& d)
{
	HANDLE hX = CreateFile(f, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (hX == INVALID_HANDLE_VALUE)
		return false;
	LARGE_INTEGER sz = { 0 };
	GetFileSizeEx(hX, &sz);
	d.resize((size_t)(sz.QuadPart / sizeof(T)));
	DWORD A = 0;
	ReadFile(hX, d.data(), (DWORD)sz.QuadPart, &A, 0);
	CloseHandle(hX);
	if (A != sz.QuadPart)
		return false;
	return true;
}


class OID
{
public:


	std::vector<unsigned char>abBinary;


	void MakeBase128(unsigned long l, int first) {
		if (l > 127) {
			MakeBase128(l / 128, 0);
		}
		l %= 128;


		if (first) {
			abBinary.push_back((unsigned char)l);
		}
		else {
			abBinary.push_back(0x80 | (unsigned char)l);
		}
	}

	std::string dec(char* d, int nBinary)
	{
		std::string s;
		char fOut[100] = { 0 };
		auto pb = d;
		int nn = 0;
		int ll = 0;
		int fOK = 0;
		while (nn < nBinary)
		{
			if (nn == 0)
			{
				//				unsigned char cl = ((*pb & 0xC0) >> 6) & 0x03;
				/*				switch (cl)
								{
								}*/
			}
			else if (nn == 1)
			{
				if (nBinary - 2 != *pb)
				{
					return "";
				}
			}
			else if (nn == 2)
			{
				sprintf_s(fOut, 100, ".%d.%d", *pb / 40, *pb % 40);
				s += fOut;
				fOK = 1;
				ll = 0;
			}
			else if ((*pb & 0x80) != 0)
			{
				ll *= 128;
				ll += (*pb & 0x7F);
				fOK = 0;
			}
			else
			{
				ll *= 128;
				ll += *pb;
				fOK = 1;

				sprintf_s(fOut, 100, ".%lu", ll);
				s += fOut;
				ll = 0;
			}

			pb++;
			nn++;
		}

		if (!fOK)
		{
			return "";
		}
		else
		{
			return s;
		}
	}

	std::vector<unsigned char> enc(char* oid)
	{
		bool isRelative = false;
		abBinary.clear();

		while (true) {

			char *p = oid;
			unsigned char cl = 0x00;
			char *q = NULL;
			int nPieces = 1;
			int n = 0;
			unsigned char b = 0;
			unsigned long l = 0;
			bool isjoint = false;

			// Alternative call: ./oid RELATIVE.2.999
			if (_strnicmp(p, "ABSOLUTE.", 9) == 0) {
				isRelative = false;
				p += 9;
			}
			else if (_strnicmp(p, "RELATIVE.", 9) == 0) {
				isRelative = true;
				p += 9;
			}
			else {
				// use the CLI option
				// isRelative = false;
			}

			cl = 0x00; // Class. Always UNIVERSAL (00)
		   // Tag for Universal Class
			if (isRelative) {
				cl |= 0x0D;
			}
			else {
				cl |= 0x06;
			}

			q = p;
			nPieces = 1;
			while (*p) {
				if (*p == '.') {
					nPieces++;
				}
				p++;
			}

			n = 0;
			b = 0;
			p = q;
			while (n < nPieces) {
				q = p;
				while (*p) {
					if (*p == '.') {
						break;
					}
					p++;
				}

				l = 0;
				if (*p == '.') {
					*p = 0;
					l = (unsigned long)atoi(q);
					q = p + 1;
					p = q;
				}
				else {
					l = (unsigned long)atoi(q);
					q = p;
				}

				/* Digit is in l. */
				if ((!isRelative) && (n == 0)) {
					if (l > 2) {
						return {};
					}
					b = 40 * ((unsigned char)l);
					isjoint = l == 2;
				}
				else if ((!isRelative) && (n == 1)) {
					if ((l > 39) && (!isjoint)) {
						return {};
					}
					if (l > 47) {
						l += 80;
						MakeBase128(l, 1);
					}
					else {
						b += ((unsigned char)l);

						abBinary.push_back(b);
					}
				}
				else {
					MakeBase128(l, 1);
				}
				n++;
			}

			if ((!isRelative) && (n < 2)) {
				return {};
			}


			break;
		}


		return abBinary;
	}
};


class HASH
{
	BCRYPT_ALG_HANDLE h;
	BCRYPT_HASH_HANDLE ha;
public:

	HASH(const wchar_t* alg = BCRYPT_SHA256_ALGORITHM)
	{
		BCryptOpenAlgorithmProvider(&h, alg, 0, 0);
		if (h)
			BCryptCreateHash(h, &ha, 0, 0, 0, 0, 0);
	}

	bool hash(const BYTE* d, DWORD sz)
	{
		if (!ha)
			return false;
		auto nt = BCryptHashData(ha, (UCHAR*)d, sz, 0);
		return (nt == 0) ? true : false;
	}

	bool get(std::vector<BYTE>& b)
	{
		DWORD hl;
		ULONG rs;
		if (!ha)
			return false;
		auto nt = BCryptGetProperty(ha, BCRYPT_HASH_LENGTH, (PUCHAR)&hl, sizeof(DWORD), &rs, 0);
		if (nt != 0)
			return false;
		b.resize(hl);
		nt = BCryptFinishHash(ha, b.data(), hl, 0);
		if (nt != 0)
			return false;
		return true;
	}

	~HASH()
	{
		if (ha)
			BCryptDestroyHash(ha);
		ha = 0;
		if (h)
			BCryptCloseAlgorithmProvider(h, 0);
		h = 0;
	}
};

inline std::vector<char> StripASNTagLength(std::vector<char>& d)
{
	std::vector<char> x = d;

	// Strip Tag
	x.erase(x.begin());
	unsigned char d0 = d[0];
	if (d0 < 127)
	{
		x.erase(x.begin());
		return x;
	}

	x.erase(x.begin());
	d0 -= 128;
	while (d0 > 0)
	{
		x.erase(x.begin());
		d0--;
	}

	return x;
}


inline void LenPush(unsigned char s, std::vector<char>& x, DWORD sz)
{
	x.push_back(s);
	if (sz <= 127)
		x.push_back((unsigned char)sz);
	else
	{
		if (sz <= 255)
		{
			x.push_back((unsigned char)0x81);
			x.push_back((unsigned char)sz);
		}
		else
			if (sz <= 65535)
			{
				x.push_back((unsigned char)0x82);
				x.push_back(HIBYTE(sz));
				x.push_back(LOBYTE(sz));
			}
			else
			{
				//*
			}
	}
}

inline std::vector<char> EncodeCertList(std::vector<PCCERT_CONTEXT>& d)
{
	// 	CertificateValues :: = SEQUENCE OF Certificate
	std::vector<char> x;
	DWORD sz = 0;
	for (auto& dd : d)
	{
		sz += dd->cbCertEncoded;
	}
	LenPush(0x30, x, sz);
	for (auto& dd : d)
	{
		std::vector<char> dz(dd->cbCertEncoded);
		memcpy(dz.data(), dd->pbCertEncoded, dd->cbCertEncoded);
		x.insert(x.end(), dz.begin(), dz.end());
	}

	return x;
}

inline std::vector<char> EncodeCRLList(std::vector<PCCRL_CONTEXT>& d)
{
	/*
		TestTest tt = { 0 };
		BYTE b1[1];
		BYTE b2[1];
		INTEGER_t ty1;
		INTEGER_t os1;
		tt.testdummy1 = &ty1;
		tt.testdummy1->size = 1;
		tt.testdummy1->buf = b1;
		tt.testdummy1->buf[0] = 0x88;

		tt.testdummy2 = &ty1;
		tt.testdummy2->size = 1;
		tt.testdummy2->buf = b2;
		tt.testdummy2->buf[0] = 0x77;

		// Encode it as DER
		std::vector<char> buff3;
		auto ec2 = der_encode(&asn_DEF_TestTest,
			&tt, [](const void *buffer, size_t size, void *app_key) ->int
		{
			std::vector<char>* x = (std::vector<char>*)app_key;
			auto es = x->size();
			x->resize(x->size() + size);
			memcpy(x->data() + es, buffer, size);
			return 0;
		}, (void*)&buff3);
	*/

	std::vector<char> x;

	/*

   RevocationValues ::=  SEQUENCE {
	  crlVals          [0] SEQUENCE OF CertificateList OPTIONAL,
	  ocspVals         [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
	  otherRevVals     [2] OtherRevVals OPTIONAL
	  }

   OtherRevVals ::= SEQUENCE {
	  OtherRevValType   OtherRevValType,
	  OtherRevVals      ANY DEFINED BY OtherRevValType
	  }

   OtherRevValType ::= OBJECT IDENTIFIER
   */

	DWORD sz = 0;
	for (auto& dd : d)
	{
		sz += dd->cbCrlEncoded;
	}
	LenPush(0x30, x, sz);
	for (auto& dd : d)
	{
		std::vector<char> dz(dd->cbCrlEncoded);
		memcpy(dz.data(), dd->pbCrlEncoded, dd->cbCrlEncoded);
		x.insert(x.end(), dz.begin(), dz.end());
	}


	// x has the seq of CRLs

	// We must also put the explicit tag 0xa0 <length>
	std::vector<char> x3;
	LenPush(0xa0, x3,(DWORD) x.size());
	x3.insert(x3.end(), x.begin(), x.end());

	std::vector<char> x2;
	LenPush(0x30, x2, (DWORD)x3.size());
	x2.insert(x2.end(), x3.begin(), x3.end());
	return x2;
}

AdES::AdES()
{

}

HRESULT AdES::VerifyB(const char* data, DWORD sz, int sidx, bool Attached, PCCERT_CONTEXT c, bool WasPDF)
{
	HRESULT hr = E_FAIL;
	bool CTFound = false;
	bool MDFound = false;
	bool TSFound = false;
	bool CHFound = false;

	if (!c || !data || !sz)
		return E_FAIL;

	auto hMsg = CryptMsgOpenToDecode(
		MY_ENCODING_TYPE,   // Encoding type
		Attached ? 0 : CMSG_DETACHED_FLAG,                    // Flags
		0,                  // Message type (get from message)
		0,         // Cryptographic provider
		NULL,               // Recipient information
		NULL);
	if (hMsg)
	{
		if (CryptMsgUpdate(
			hMsg,            // Handle to the message
			(BYTE*)data,   // Pointer to the encoded BLOB
			(DWORD)sz,   // Size of the encoded BLOB
			TRUE))           // Last call
		{
			DWORD da = 0;
			if (CryptMsgGetParam(hMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, sidx, 0, &da))
			{
				std::vector<char> ca;
				ca.resize(da);
				if (CryptMsgGetParam(hMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, sidx, ca.data(), &da))
				{
					CRYPT_ATTRIBUTES* si = (CRYPT_ATTRIBUTES*)ca.data();
					for (DWORD g = 0; g < si->cAttr; g++)
					{
						CRYPT_ATTRIBUTE& attr = si->rgAttr[g];
						if (strcmp(attr.pszObjId, "1.2.840.113549.1.9.3") == 0) // Content Type
						{
							CTFound = true;
						}
						if (strcmp(attr.pszObjId, "1.2.840.113549.1.9.4") == 0) // Digest
						{
							MDFound = true;
						}
						if (strcmp(attr.pszObjId, "1.2.840.113549.1.9.5") == 0 && attr.cValue == 1) // Timestamp
						{
							std::vector<char> bu(10000);
							DWORD xd = 10000;
							if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szOID_RSA_signingTime, attr.rgValue[0].pbData, attr.rgValue[0].cbData, 0, 0, (void*)bu.data(), &xd))
							{
								TSFound = true;
							}
						}
						if (strcmp(attr.pszObjId, "1.2.840.113549.1.9.16.2.47") == 0 && attr.cValue == 1) // ESSCertificateV2
						{
							SigningCertificateV2* v = 0;
							auto rval = asn_DEF_SigningCertificateV2.ber_decoder(0,
								&asn_DEF_SigningCertificateV2,
								(void **)&v,
								attr.rgValue[0].pbData, attr.rgValue[0].cbData, 0);
							if (v)
							{
								// Check the certificate hash
								std::vector<BYTE> dhash;
								HASH hash(BCRYPT_SHA256_ALGORITHM);
								hash.hash(c->pbCertEncoded, c->cbCertEncoded);
								hash.get(dhash);
								if (v->certs.list.count == 1 && v->certs.list.array[0]->certHash.size == dhash.size())
								{
									if (memcmp(v->certs.list.array[0]->certHash.buf, dhash.data(), dhash.size()) == 0)
										CHFound = true;
								}
								asn_DEF_SigningCertificateV2.free_struct(&asn_DEF_SigningCertificateV2, v, 0);
								v = 0;
							}
						}
					}
				}
			}
		}
	}

	if (hMsg)
	{
		CryptMsgClose(hMsg);
		hMsg = 0;
	}
	if (WasPDF)
		TSFound = true;

	if (CTFound && MDFound && TSFound && CHFound)
		hr = S_OK;

	return hr;
}

HRESULT AdES::VerifyU(const char* data, DWORD sz, bool Attached, int TSServerSignIndex)
{

	HRESULT hr = E_FAIL;
	auto hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE,Attached ? 0 : CMSG_DETACHED_FLAG,0,0,0,0);
	if (hMsg)
	{
		if (CryptMsgUpdate(hMsg, (BYTE*)data, (DWORD)sz, TRUE))
		{
			std::vector<char> ca;
			DWORD da = 0;
			if (CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, TSServerSignIndex, 0, &da))
			{
				ca.resize(da);
				if (CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, TSServerSignIndex, ca.data(), &da))
				{
				}
			}
		}
	}
	return hr;
}

HRESULT AdES::VerifyT(const char* data, DWORD sz, PCCERT_CONTEXT* pX, bool Attached, int TSServerSignIndex, FILETIME* ft, PCRYPT_TIMESTAMP_CONTEXT* ptc)
{
	HRESULT hr = E_FAIL;

	auto hMsg = CryptMsgOpenToDecode(
		MY_ENCODING_TYPE,   // Encoding type
		Attached ? 0 : CMSG_DETACHED_FLAG,                    // Flags
		0,                  // Message type (get from message)
		0,         // Cryptographic provider
		NULL,               // Recipient information
		NULL);
	if (hMsg)
	{
		if (CryptMsgUpdate(
			hMsg,            // Handle to the message
			(BYTE*)data,   // Pointer to the encoded BLOB
			(DWORD)sz,   // Size of the encoded BLOB
			TRUE))           // Last call
		{
			std::vector<char> ca;
			DWORD da = 0;

			if (CryptMsgGetParam(
				hMsg,                  // Handle to the message
				CMSG_ENCRYPTED_DIGEST,  // Parameter type
				TSServerSignIndex,                     // Index
				NULL,                  // Address for returned information
				&da))       // Size of the returned information
			{
				std::vector<char> EH(da);
				if (CryptMsgGetParam(
					hMsg,                  // Handle to the message
					CMSG_ENCRYPTED_DIGEST,  // Parameter type
					TSServerSignIndex,                     // Index
					(BYTE*)EH.data(),                  // Address for returned information
					&da))       // Size of the returned information
				{
					EH.resize(da);
					if (CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, TSServerSignIndex, 0, &da))
					{
						ca.resize(da);
						if (CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, TSServerSignIndex, ca.data(), &da))
						{
							CRYPT_ATTRIBUTES* si = (CRYPT_ATTRIBUTES*)ca.data();
							if (si->cAttr >= 1)
							{
								for (DWORD a = 0; a < si->cAttr; a++)
								{
									if (strcmp(si->rgAttr[a].pszObjId, "1.2.840.113549.1.9.16.2.14") == 0 && si->rgAttr[a].cValue == 1)
									{
										auto& v = si->rgAttr[a].rgValue[0];
										// It is already decoded 
										PCRYPT_TIMESTAMP_CONTEXT re = 0;
										BYTE* b = (BYTE*)v.pbData;
										auto sz3 = v.cbData;
										auto res = CryptVerifyTimeStampSignature(b, sz3, (BYTE*)EH.data(), (DWORD)EH.size(), 0, &re, pX, 0);
										if (!res)
											hr = E_FAIL;
										else
										{
											if (ft)
												*ft = re->pTimeStamp->ftTime;
											if (ptc)
												*ptc = re;
											else
												CryptMemFree(re);
											hr = S_OK;
											break;
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (hMsg)
	{
		CryptMsgClose(hMsg);
		hMsg = 0;
	}
	return hr;
}

HRESULT AdES::TimeStamp(SIGNPARAMETERS& sparams, const char* data, DWORD sz, std::vector<char>& Result, const wchar_t* url, const char* alg)
{
	CRYPT_TIMESTAMP_PARA params = { 0,TRUE,{},0,0 };
	if (sparams.TSPolicy.length())
		params.pszTSAPolicyId = sparams.TSPolicy.c_str();

	CRYPT_TIMESTAMP_CONTEXT*re;
	auto flg = TIMESTAMP_VERIFY_CONTEXT_SIGNATURE;

	if (!CryptRetrieveTimeStamp(url, flg, 0, alg, &params, (BYTE*)data, (DWORD)sz, &re, 0, 0))
		return E_FAIL;
	std::vector<char>& CR = Result;
	CR.resize(re->cbEncoded);
	memcpy(CR.data(), re->pbEncoded, re->cbEncoded);
	CryptMemFree(re);
	return S_OK;
}

HRESULT AdES::Verify(const char* data, DWORD sz, LEVEL& lev, const char* omsg, DWORD len, std::vector<char>* msg, std::vector<PCCERT_CONTEXT>* Certs, VERIFYRESULTS* vr, bool WasPDF)
{
	auto hr = E_FAIL;
	using namespace std;

	CRYPT_VERIFY_MESSAGE_PARA VerifyParams = { 0 };
	VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
	VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
	VerifyParams.hCryptProv = 0;
	VerifyParams.pfnGetSignerCertificate = NULL;
	VerifyParams.pvGetArg = NULL;
	std::vector<char> zud;
	DWORD pzud = 100000;
	int NumVer = 0;

	for (int i = 0; ; i++)
	{
		PCCERT_CONTEXT c = 0;
		int ZRS = omsg ? 1 : CryptVerifyMessageSignature(&VerifyParams, i, (BYTE*)data, (DWORD)sz, 0, &pzud, 0);
		if (ZRS == 1)
		{
			zud.resize(pzud);
			const BYTE * rgpbToBeSigned[1];
			rgpbToBeSigned[0] = (BYTE*)omsg;
			DWORD bb[1];
			bb[0] = len;
			ZRS = omsg ? CryptVerifyDetachedMessageSignature(&VerifyParams, i, (BYTE*)data, (DWORD)sz, 1, rgpbToBeSigned, bb, &c) : CryptVerifyMessageSignature(&VerifyParams, i, (BYTE*)data, (DWORD)sz, (BYTE*)zud.data(), &pzud, &c);
		}
		if (ZRS == 0)
			break;
		if (ZRS == 1)
		{
			if (c && Certs)
				Certs->push_back(c);
			if (NumVer == 0 && msg)
				*msg = zud;

			NumVer++;
			hr = S_OK;
			lev = LEVEL::CMS;

			// Check now BES
			auto hr1 = VerifyB(data, sz, i, omsg ? false : true, c,WasPDF);
			if (SUCCEEDED(hr1))
			{
				lev = LEVEL::B;
				// Check now T
				FILETIME ft = { 0 };
				auto hr2 = VerifyT(data, sz, 0, omsg ? false : true, i, &ft);
				if (SUCCEEDED(hr2))
					lev = LEVEL::T;
			}

			if (!Certs && c)
				CertFreeCertificateContext(c);
			c = 0;
		}
	}

	if (SUCCEEDED(hr) && vr)
	{
		// Return also the policy and other stuff
		auto hMsg = CryptMsgOpenToDecode(
			MY_ENCODING_TYPE,
			(omsg == 0) ? 0 : CMSG_DETACHED_FLAG,
			0,
			0,
			NULL,
			NULL);
		if (hMsg)
		{
			if (CryptMsgUpdate(
				hMsg,
				(BYTE*)data,
				(DWORD)sz,
				TRUE))
			{
				DWORD da = 0;
				for (DWORD sidx = 0; ; sidx++)
				{
					VERIFYRESULT vrs;
					if (CryptMsgGetParam(hMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, sidx, 0, &da))
					{
						std::vector<char> ca;
						ca.resize(da);
						if (CryptMsgGetParam(hMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, sidx, ca.data(), &da))
						{
							CRYPT_ATTRIBUTES* si = (CRYPT_ATTRIBUTES*)ca.data();
							for (DWORD g = 0; g < si->cAttr; g++)
							{
								CRYPT_ATTRIBUTE& attr = si->rgAttr[g];
								if (strcmp(attr.pszObjId, "1.2.840.113549.1.9.16.2.15") == 0 && attr.cValue == 1) // SignaturePolicyId
								{
									SignaturePolicyIdentifier* v = 0;
									auto rval = asn_DEF_SignaturePolicyIdentifier.ber_decoder(0,
										&asn_DEF_SignaturePolicyIdentifier,
										(void **)&v,
										attr.rgValue[0].pbData, attr.rgValue[0].cbData, 0);
									if (v)
									{
										std::vector<char> sp(v->choice.signaturePolicyId.sigPolicyId.size + 1);
										memcpy_s(sp.data(), v->choice.signaturePolicyId.sigPolicyId.size + 1, v->choice.signaturePolicyId.sigPolicyId.buf, v->choice.signaturePolicyId.sigPolicyId.size);
										OID oid;
										string sdec = oid.dec(sp.data(), v->choice.signaturePolicyId.sigPolicyId.size);
										vrs.Policy = sdec;
										asn_DEF_SignaturePolicyIdentifier.free_struct(&asn_DEF_SignaturePolicyIdentifier, v, 0);
										v = 0;
									}
								}
								if (strcmp(attr.pszObjId, "1.2.840.113549.1.9.16.2.16") == 0 && attr.cValue == 1) // CommitmentTypeIndication
								{
									CommitmentTypeIndication* v = 0;
									auto rval = asn_DEF_CommitmentTypeIndication.ber_decoder(0,
										&asn_DEF_CommitmentTypeIndication,
										(void **)&v,
										attr.rgValue[0].pbData, attr.rgValue[0].cbData, 0);
									if (v)
									{
										std::vector<char> sp(v->commitmentTypeId.size + 1);
										memcpy_s(sp.data(), v->commitmentTypeId.size + 1, v->commitmentTypeId.buf, v->commitmentTypeId.size);
										OID oid;
										string sdec = oid.dec(sp.data(), v->commitmentTypeId.size);
										vrs.Commitment = sdec;
										asn_DEF_CommitmentTypeIndication.free_struct(&asn_DEF_CommitmentTypeIndication, v, 0);
										v = 0;
									}
								}
							}
						}
						vr->Results.push_back(vrs);
					}
					else
						break;
				}
			}
			CryptMsgClose(hMsg);
			hMsg = 0;
		}
	}

	return hr;
}


HRESULT AdES::GetEncryptedHash(const char*d, DWORD sz, PCCERT_CONTEXT ctx, CRYPT_ALGORITHM_IDENTIFIER hash, std::vector<char>& rs)
{
	using namespace std;

	/*
	_CRYPT_SIGN_MESSAGE_PARA spar = { 0 };
	spar.cbSize = sizeof(spar);
	spar.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	spar.pSigningCert = Certificates[0];
	spar.HashAlgorithm = Params.HashAlgorithm;
	BYTE* bs = (BYTE*)s.data();
	DWORD rbs[1] = { 0 };
	rbs[0] = s.size();
	DWORD blb = 0;

	const BYTE* MessageArray[] = { (BYTE*)s.data() };
	CryptSignMessage(&spar, true, 1, MessageArray, rbs, 0, &blb);
	std::vector<char> Sig(blb);
	CryptSignMessage(&spar, true, 1, MessageArray, rbs, (BYTE*)Sig.data(), &blb);
	Sig.resize(blb);
	string dss = XML3::Char2Base64((const char*)Sig.data(), Sig.size(), false);
	sv.SetContent(dss.c_str());
*/
	HRESULT hr = E_FAIL;
	std::vector<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE> PrivateKeys;
	CMSG_SIGNER_ENCODE_INFO Signer = { 0 };
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE a = 0;
	DWORD ks = 0;
	BOOL bfr = false;
	CryptAcquireCertificatePrivateKey(ctx, 0, 0, &a, &ks, &bfr);
	if (a)
		Signer.hCryptProv = a;
	if (bfr)
		PrivateKeys.push_back(a);
	Signer.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
	Signer.pCertInfo = ctx->pCertInfo;
	Signer.dwKeySpec = ks;
	Signer.HashAlgorithm = hash;
	Signer.pvHashAuxInfo = NULL;


	CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo = { 0 };

	SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
	SignedMsgEncodeInfo.cSigners = 1;
	SignedMsgEncodeInfo.rgSigners = &Signer;
	SignedMsgEncodeInfo.cCertEncoded = 0;
	SignedMsgEncodeInfo.rgCertEncoded = 0;
	SignedMsgEncodeInfo.rgCrlEncoded = NULL;


	auto cbEncodedBlob = CryptMsgCalculateEncodedLength(
		MY_ENCODING_TYPE,     // Message encoding type
		CMSG_DETACHED_FLAG,
		CMSG_SIGNED,          // Message type
		&SignedMsgEncodeInfo, // Pointer to structure
		NULL,                 // Inner content OID
		(DWORD)sz);
	if (cbEncodedBlob)
	{
		auto hMsg = CryptMsgOpenToEncode(
			MY_ENCODING_TYPE,        // encoding type
			CMSG_DETACHED_FLAG,
			CMSG_SIGNED,             // message type
			&SignedMsgEncodeInfo,    // pointer to structure
			NULL,                    // inner content OID
			NULL);
		if (hMsg)
		{
			// Add the signature
			std::vector<char> Sig2(cbEncodedBlob);
			if (CryptMsgUpdate(hMsg, (BYTE*)d, (DWORD)sz, true))
			{
				if (CryptMsgGetParam(
					hMsg,               // Handle to the message
					CMSG_CONTENT_PARAM, // Parameter type
					0,                  // Index
					(BYTE*)Sig2.data(),      // Pointer to the BLOB
					&cbEncodedBlob))    // Size of the BLOB
				{
					Sig2.resize(cbEncodedBlob);

					CryptMsgClose(hMsg);
					hMsg = 0;


					hMsg = CryptMsgOpenToDecode(
						MY_ENCODING_TYPE,   // Encoding type
						CMSG_DETACHED_FLAG,
						0,                  // Message type (get from message)
						0,         // Cryptographic provider
						NULL,               // Recipient information
						NULL);
					if (hMsg)
					{
						if (CryptMsgUpdate(
							hMsg,            // Handle to the message
							(BYTE*)Sig2.data(),   // Pointer to the encoded BLOB
							(DWORD)Sig2.size(),   // Size of the encoded BLOB
							TRUE))           // Last call
						{

							if (CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, 0, NULL, &cbEncodedBlob))
							{
								rs.resize(cbEncodedBlob);
								if (CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, 0, (BYTE*)rs.data(), &cbEncodedBlob))
								{
									rs.resize(cbEncodedBlob);
									hr = S_OK;
								}
							}

						}
					}


				}
			}
			if (hMsg)
				CryptMsgClose(hMsg);
			hMsg = 0;
		}
	}

	for (auto& pk : PrivateKeys)
	{
		if (NCryptIsKeyHandle(pk))
			NCryptFreeObject(pk);
		else
			CryptReleaseContext(pk, 0);
	}

	return hr;
}

std::tuple<std::shared_ptr<XML3::XMLElement>, std::shared_ptr<XML3::XMLElement>> XMLAddC(XML3::XMLElement& xusp,const std::vector<AdES::CERT>& Certificates,std::function<void(XML3::XMLElement& r, PCCERT_CONTEXT C)> putcert, std::function<void(XML3::XMLElement& r, PCCRL_CONTEXT C)> putcrl)
{
	using namespace std;
	XML3::XMLElement c1 = "xades141:CompleteCertificateRefsV2";
	c1.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
	c1.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
	c1.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";

	auto xcc1 = xusp.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(c1));

	for (auto&cert : Certificates)
	{
		putcert(*xcc1, cert.cert.cert);

		for (auto& cert2 : cert.More)
		{
			putcert(*xcc1, cert2.cert);
		}
	}
	XML3::XMLElement c2 = "xades:CompleteRevocationRefs";
	c2.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
	c2.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
	c2.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";
	auto xcc2a = xusp.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(c2));
	XML3::XMLElement c2a = "xades:CRLRefs";
	auto xcc2 = xcc2a->InsertElement((size_t)-1, std::forward<XML3::XMLElement>(c2a));
	for (auto&cert : Certificates)
	{
		for (auto&crl : cert.cert.Crls)
		{
			putcrl(*xcc2, crl);
		}

		for (auto& cert2 : cert.More)
		{
			for (auto&crl : cert2.Crls)
			{
				putcrl(*xcc2, crl);
			}
		}
	}
	return make_tuple< shared_ptr<XML3::XMLElement>, shared_ptr<XML3::XMLElement>>(std::forward<shared_ptr<XML3::XMLElement>>(xcc1), std::forward<shared_ptr<XML3::XMLElement>>(xcc2a));
}

void XMLAddX(AdES& ad,AdES::SIGNPARAMETERS& Params,std::string& CanonicalizationString,XML3::XMLElement& xusp, XML3::XMLSerialization& ser,std::shared_ptr<XML3::XMLElement> xcc1, std::shared_ptr<XML3::XMLElement> xcc2a)
{
	using namespace std;
	auto s1 = xcc1->Serialize(&ser);
	auto s2 = xcc2a->Serialize(&ser);
	s1 += s2;
	XML3::XMLElement ccc1 = "xades141:RefsOnlyTimeStampV2";
	auto xcc3 = xusp.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(ccc1));
	(*xcc3)["ds:CanonicalizationMethod"].vv("Algorithm") = CanonicalizationString;
	auto& h1 = xcc3->AddElement("xades:EncapsulatedTimeStamp");

	// Find the timestamp
	std::vector<char> tsr;
	ad.TimeStamp(Params, (char*)s1.data(), (DWORD)s1.size(), tsr, Params.TSServer.c_str());
	string b = XML3::Char2Base64(tsr.data(), tsr.size(), false);
	h1.SetContent(b.c_str());

}

void XMLRemoveComments(XML3::XMLElement& el)
{
	for (auto& ee : el)
	{
		XMLRemoveComments(ee);
	}

	el.GetComments().clear();
}
void XMLRemoveCDatas(XML3::XMLElement& el)
{
	for (auto& ee : el)
	{
		XMLRemoveCDatas(ee);
	}

	el.GetCDatas().clear();
}


void XMLAddXL(XML3::XMLElement& xusp, const std::vector<AdES::CERT>& Certificates)
{
	using namespace std;
	XML3::XMLElement d1 = "xades132:CertificateValues";
	d1.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
	d1.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
	d1.vv("xmlns:xades132") = "http://uri.etsi.org/01903/v1.3.2#";
	d1.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";


	auto addcert = [&](PCCERT_CONTEXT c)
	{
		XML3::XMLElement f1 = "xades132:EncapsulatedX509Certificate";

		string d3 = XML3::Char2Base64((const char*)c->pbCertEncoded, c->cbCertEncoded, false);
		f1.SetContent(d3.c_str());

		d1.AddElement(f1);

	};

	for (auto&cert : Certificates)
	{
		addcert(cert.cert.cert);
		for (auto& cert2 : cert.More)
		{
			addcert(cert2.cert);
		}
	}
	auto xdd1 = xusp.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(d1));

	XML3::XMLElement dd2 = "xades132:RevocationValues";
	dd2.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
	dd2.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
	dd2.vv("xmlns:xades132") = "http://uri.etsi.org/01903/v1.3.2#";
	dd2.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";

	XML3::XMLElement dx3 = "xades132:CRLValues";

	auto addcrl = [&](PCCRL_CONTEXT c)
	{
		XML3::XMLElement f1 = "xades132:EncapsulatedCRLValue";

		string d3 = XML3::Char2Base64((const char*)c->pbCrlEncoded, c->cbCrlEncoded, false);
		f1.SetContent(d3.c_str());
		dx3.AddElement(f1);

	};

	for (auto&cert : Certificates)
	{
		for (auto& crl : cert.cert.Crls)
			addcrl(crl);

		for (auto& cert2 : cert.More)
		{
			for (auto& crl : cert2.Crls)
				addcrl(crl);
		}
	}
	dd2.AddElement(dx3);
	auto xdd2 = xusp.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(dd2));
}

HRESULT AdES::XMLSign(LEVEL lev, std::vector<FILEREF>& dat,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& Signature)
{
//	Params.XMLComments = true;
	using namespace std;

	string CanonicalizationString = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
	if (Params.XMLComments)
		CanonicalizationString = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

	auto guidcr = []() -> string
	{
		GUID g;
		CoCreateGuid(&g);
		wchar_t s[100] = { 0 };
		StringFromGUID2(g, s, 100);
		s[wcslen(s) - 1] = 0;
		return (string)XML3::XMLU(s + 1);
	};

	auto certsrl = [](PCCERT_CONTEXT c) -> unsigned long long
	{
		BYTE *pbName = c->pCertInfo->SerialNumber.pbData;
		string theString;
		for (int i = c->pCertInfo->SerialNumber.cbData - 1; i >= 0; i--)
		{
			char hex[10];
			sprintf_s(hex, 10, "%02x", pbName[i]);
			theString += hex;
		}
		unsigned long long x = 0;
		std::stringstream ss;
		ss << std::hex << theString;
		ss >> x;
		return x;
	};

	std::vector<XML3::XMLElement*> CollectionForA;


	auto algfrom = [&]() -> string
	{
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha256) == 0)
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha384) == 0)
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha512) == 0)
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
		if (strcmp(Params.HashAlgorithm.pszObjId, "2.16.840.1.101.3.4.2.8") == 0)
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha3-256";
		return "";
	};
	auto alg2from = [&]() -> string
	{
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			return "http://www.w3.org/2000/09/xmldsig#sha1";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha256) == 0)
			return "http://www.w3.org/2001/04/xmlenc#sha256";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha384) == 0)
			return "http://www.w3.org/2001/04/xmlenc#sha384";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha512) == 0)
			return "http://www.w3.org/2001/04/xmlenc#sha512";
		if (strcmp(Params.HashAlgorithm.pszObjId, "2.16.840.1.101.3.4.2.8") == 0)
			return "http://www.w3.org/2001/04/xmlenc#sha3-256";
		return "";
	};
	auto alg3from = [&]() -> LPWSTR
	{
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			return BCRYPT_SHA1_ALGORITHM;
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha256) == 0)
			return BCRYPT_SHA256_ALGORITHM;
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha384) == 0)
			return BCRYPT_SHA384_ALGORITHM;
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha512) == 0)
			return BCRYPT_SHA512_ALGORITHM;
		if (strcmp(Params.HashAlgorithm.pszObjId, "2.16.840.1.101.3.4.2.8") == 0)
			return L"SHA3-256";
		
		return L"";
	};

	auto remprefix = [](XML3::XMLElement& r)
	{
		std::vector<shared_ptr<XML3::XMLElement>> allc;
		r.GetAllChildren(allc);
		for (auto a : allc)
		{
			if (strncmp(a->GetElementName().c_str(), "ds:", 3) == 0)
			{
				string n = a->GetElementName().c_str() + 3;
				a->SetElementName(n.c_str());
			}
		}

	};

	auto putcert = [&](XML3::XMLElement& r,PCCERT_CONTEXT C)
	{
		auto& xce = r.AddElement("xades:Cert");
		auto& xced = xce.AddElement("xades:CertDigest");
		char d[1000];
		xced["ds:DigestMethod"].vv("Algorithm") = alg2from();


		if (Params.ConformanceLevel != 4)
		{
			auto srl = certsrl(C);
			sprintf_s(d, 1000, "%llu", (unsigned long long)srl);
			auto& xces = xce.AddElement("xades:IssuerSerialV2");
			xces["ds:X509SerialNumber"].SetContent(d);
		}
		std::vector<BYTE> dhash3;
		LPWSTR alg3 = alg3from();
		HASH hash33(alg3);
		hash33.hash(C->pbCertEncoded, C->cbCertEncoded);
		hash33.get(dhash3);
		string dx = XML3::Char2Base64((char*)dhash3.data(), dhash3.size(), false);
		xced["ds:DigestValue"].SetContent(dx.c_str());
	};

	auto putcrl = [&](XML3::XMLElement& r, PCCRL_CONTEXT C)
	{
		auto& xce = r.AddElement("xades:CRLRef");
		auto& xced = xce.AddElement("xades:DigestAlgAndValue");
		xced["ds:DigestMethod"].vv("Algorithm") = alg2from();


		std::vector<BYTE> dhash3;
		LPWSTR alg3 = alg3from();
		HASH hash33(alg3);
		hash33.hash(C->pbCrlEncoded, C->cbCrlEncoded);
		hash33.get(dhash3);
		string dx = XML3::Char2Base64((char*)dhash3.data(), dhash3.size(), false);
		xced["ds:DigestValue"].SetContent(dx.c_str());
	};



	auto hr = E_FAIL;
	Signature.clear();
	if (Params.Attached == ATTACHTYPE::ENVELOPED)
	{
		if (dat.size() != 1)
			return E_INVALIDARG;
		if (dat[0].sz != 0)
			return E_INVALIDARG;
	}
	if (Certificates.empty())
		return E_INVALIDARG;
	if (Params.Attached == ATTACHTYPE::ENVELOPED)
	{
		if (Certificates.size() != 1)
			return E_NOTIMPL;
	}

	//string s;

	char d[1000] = { 0 };

	XML3::XMLSerialization ser;
	ser.Canonical = true;
	std::vector<BYTE> dhash;
	XML3::XML x;
	LPWSTR alg = alg3from();
	string d2;


	for (size_t iCert = 0; iCert < Certificates.size(); iCert++)
	{

		// ds:Signature
		string id1 = guidcr();

		XML3::XMLElement ds_Signature;
		ds_Signature.SetElementName("ds:Signature");
		ds_Signature.vv(lev == LEVEL::XMLDSIG ? "xmlns" : "xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
		if (lev != LEVEL::XMLDSIG)
			ds_Signature.vv("Id") = "xmldsig-" + id1;

		XML3::XMLElement ds_SignedInfo;
		ds_SignedInfo.SetElementName("ds:SignedInfo");
		if (lev == LEVEL::XMLDSIG)
			ds_SignedInfo.vv("xmlns") = "http://www.w3.org/2000/09/xmldsig#";
		else
		{
			ds_SignedInfo.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
		}

		if (Params.xextras.length())
		{
			XML3::XML extr(Params.xextras.c_str(),Params.xextras.size());
			ds_SignedInfo.AddElement(extr.GetRootElement());
		}

		ds_SignedInfo["ds:CanonicalizationMethod"].vv("Algorithm") = CanonicalizationString;
		ds_SignedInfo["ds:SignatureMethod"].vv("Algorithm") = algfrom();

		for (size_t jidx = 0;  jidx < dat.size() ; jidx++)
		{
			auto&  data = dat[jidx];
			
			auto URIRef = data.ref;
			string ss;
			if (data.sz == 0)
			{
				x.Clear();
				auto xp = x.Parse((char*)data.data, strlen((char*)data.data));
				if (xp != XML3::XML_PARSE::OK)
					return E_UNEXPECTED;

				// Remove comments
				if (!Params.XMLComments)
					XMLRemoveComments(x.GetRootElement());
				XMLRemoveCDatas(x.GetRootElement());

				if (Params.Attached == ATTACHTYPE::ENVELOPING)
				{
					XML3::XMLElement enveloping = lev == LEVEL::XMLDSIG ? "Object" : "ds:Object";
					enveloping.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
					enveloping.vv("Id") = URIRef;
					enveloping.AddElement(x.GetRootElement());
					ss = enveloping.Serialize(&ser);
				}
				else
					ss = x.GetRootElement().Serialize(&ser);
			}
			else
			{
				ss.assign((char*)data.data, data.sz);
			}

			auto& ref1 = ds_SignedInfo.AddElement("ds:Reference");
			sprintf_s(d, 1000, "data%llu",(unsigned long long) jidx);
			ref1.vv("Id") = d;
			ref1.vv("URI") = "";
			if (URIRef && Params.Attached == ATTACHTYPE::DETACHED)
				ref1.vv("URI") = URIRef;
			if (URIRef && Params.Attached == ATTACHTYPE::ENVELOPING)
			{
				// With #
				sprintf_s(d, 1000, "#%s", URIRef);
				ref1.vv("URI") = d;
			}

			if (data.sz == 0)
			{
				if (Params.Attached == ATTACHTYPE::ENVELOPED)
					ref1["ds:Transforms"]["ds:Transform"].vv("Algorithm") = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
			}
			ref1["ds:DigestMethod"].vv("Algorithm") = alg2from();

			// Hash
			HASH hash(alg);
			hash.hash((BYTE*)ss.c_str(), (DWORD)ss.length());
			hash.get(dhash);
			d2 = XML3::Char2Base64((const char*)dhash.data(), dhash.size(), false);
			ref1["ds:DigestValue"].SetContent(d2.c_str());

			CollectionForA.push_back(&ref1);
		}



		// Key Info
		string _ds_KeyInfo = R"(<ds:KeyInfo>
	<ds:X509Data>
		<ds:X509Certificate>
		</ds:X509Certificate>
	</ds:X509Data>
</ds:KeyInfo>
	)";
		XML3::XMLElement ki = _ds_KeyInfo.c_str();
		if (lev != LEVEL::XMLDSIG)
		{
			if (Params.ASiC)
			{
				ki.vv("xmlns:asic") = "http://uri.etsi.org/02918/v1.2.1#";
				ki.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
				ki.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
				ki.vv("xmlns:xsi") = "http://www.w3.org/2001/XMLSchema-instance";

			}
			else
				ki.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
			sprintf_s(d, 1000, "xmldsig-%s-keyinfo", id1.c_str());
			ki.vv("Id") = d;
		}

		auto& kiel = ki["ds:X509Data"]["ds:X509Certificate"];
		string d3 = XML3::Char2Base64((const char*)Certificates[iCert].cert.cert->pbCertEncoded, Certificates[iCert].cert.cert->cbCertEncoded, false);
		kiel.SetContent(d3.c_str());

		// Objects
		XML3::XMLElement o2 = "<ds:Object/>";
		shared_ptr<XML3::XMLElement> tscontent;
		shared_ptr<XML3::XMLElement> cc2;
		shared_ptr<XML3::XMLElement> cc1;
		if (lev != LEVEL::XMLDSIG)
		{
			auto& xqp = o2.AddElement("xades:QualifyingProperties");
			xqp.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
			xqp.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";
			xqp.vv("Target") = "#xmldsig-" + id1;

			auto& xsp = xqp.AddElement("xades:SignedProperties");

			// Up stuff xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:xades141="http://uri.etsi.org/01903/v1.4.1#" 
			if (Params.ASiC)
			{
				xsp.vv("xmlns:asic") = "http://uri.etsi.org/02918/v1.2.1#";
				xsp.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
				xsp.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
				xsp.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";
				xsp.vv("xmlns:xsi") = "http://www.w3.org/2001/XMLSchema-instance";

			}
			else
			{
				xsp.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
				xsp.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
				xsp.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";
			}

			sprintf_s(d, 1000, "xmldsig-%s-sigprops", id1.c_str());
			xsp.vv("Id") = d;

			auto& xssp = xsp.AddElement("xades:SignedSignatureProperties");

			auto& xst = xssp.AddElement("xades:SigningTime");

			// Find the time (UTC)
			SYSTEMTIME sT;
			GetSystemTime(&sT);
			// 2018-09-04T10:35:44.602-04:00
			sprintf_s(d, 1000, "%04u-%02u-%02uT%02u:%02u:%02uZ", sT.wYear, sT.wMonth, sT.wDay, sT.wHour, sT.wMinute, sT.wSecond);
			xst.SetContent(d);

			auto& xsc = xssp.AddElement("xades:SigningCertificateV2");
			putcert(xsc, Certificates[iCert].cert.cert);
		
			

			auto& xsdop = xsp.AddElement("xades:SignedDataObjectProperties");


			for (size_t jidx = 0; jidx < dat.size(); jidx++)
			{
				auto&  data = dat[jidx];
				if (data.mime.length())
				{
					auto& x1 = xsdop.AddElement("xades:DataObjectFormat");
					sprintf_s(d, 1000, "#data%llu", (unsigned long long)jidx);
					x1.vv("ObjectReference") = d;

					auto& x2 = x1.AddElement("xades:MimeType");
					x2.SetContent(data.mime.c_str());

				}
			}

			// And a ref3 DataObjectFormat
			if (true)
			{
				auto& x1 = xsdop.AddElement("xades:DataObjectFormat");
				sprintf_s(d, 1000, "#SignedInfoKeyProperties");
				x1.vv("ObjectReference") = d;

				auto& x2 = x1.AddElement("xades:MimeType");
				x2.SetContent("application/x-x509-ca-cert");
			}

			// Policy
			if (Params.Policy.length())
			{
				auto& xspol = xssp.AddElement("xades:SignaturePolicyIdentifier");
				auto& xspolid = xspol.AddElement("xades:SignaturePolicyId");
				auto& xspolid2 = xspolid.AddElement("xades:SigPolicyId");
				auto& xi2id = xspolid2.AddElement("xades:Identifier");
				xi2id.SetContent(Params.Policy.c_str());
				auto& xspolid3 = xspolid.AddElement("xades:SigPolicyHash");
				xspolid3["ds:DigestMethod"].vv("Algorithm") = alg2from();
				HASH hb(alg3from());
				hb.hash((BYTE*)Params.Policy.data(), (DWORD)Params.Policy.size());
				std::vector<BYTE> hbb;
				hb.get(hbb);
				string dd2 = XML3::Char2Base64((char*)hbb.data(), hbb.size(), false);
				xspolid3["ds:DigestValue"].SetContent(dd2.c_str());
			}


			// Commitment
			if (Params.commitmentTypeOid.length())
			{
				auto& xcti = xsdop.AddElement("xades:CommitmentTypeIndication");
				auto& xctid = xcti.AddElement("xades:CommitmentTypeId"	);
				auto& xiid = xctid.AddElement("xades:Identifier");
				const string& cmt = Params.commitmentTypeOid;
				if (cmt == "1.2.840.113549.1.9.16.6.1")
				{
					xiid.SetContent("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin");
					xctid.AddElement("xades:Description").SetContent("Indicates that the signer recognizes to have created, approved and sent the signed data object");
				}
				if (cmt == "1.2.840.113549.1.9.16.6.2")
				{
					xiid.SetContent("http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt");
					xctid.AddElement("xades:Description").SetContent("Indicates that signer recognizes to have received the content of the signed data object");
				}
				if (cmt == "1.2.840.113549.1.9.16.6.3")
				{
					xiid.SetContent("http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery");
					xctid.AddElement("xades:Description").SetContent("Indicates that the TSP providing that indication has delivered a signed data object in a local store accessible to the recipient of the signed data object");
				}
				if (cmt == "1.2.840.113549.1.9.16.6.4")
				{
					xiid.SetContent("http://uri.etsi.org/01903/v1.2.2#ProofOfSender");
					xctid.AddElement("xades:Description").SetContent("Indicates that the entity providing that indication has sent the signed data object (but not necessarily created it)");
				}
				if (cmt == "1.2.840.113549.1.9.16.6.5")
				{
					xiid.SetContent("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval");
					xctid.AddElement("xades:Description").SetContent("Indicates that the signer has approved the content of the signed data object");
				}
				if (cmt == "1.2.840.113549.1.9.16.6.6")
				{
					xiid.SetContent("http://uri.etsi.org/01903/v1.2.2#ProofOfCreation");
					xctid.AddElement("xades:Description").SetContent("Indicates that the signer has created the signed data object (but not necessarily approved, nor sent it)");
				}
				/*auto& xasdo = */xcti.AddElement("xades:AllSignedDataObjects");
			}


			string sps = xsp.Serialize(&ser);
			string spk = ki.Serialize(&ser);

			auto& ref2 = ds_SignedInfo.AddElement("ds:Reference");
			sprintf_s(d, 1000, "#xmldsig-%s-sigprops", id1.c_str());
			ref2.vv("Id") = "SignedInfoSignedProperties";
			ref2.vv("URI") = d;
			ref2.vv("Type") = "http://uri.etsi.org/01903#SignedProperties";


			ref2["ds:Transforms"]["ds:Transform"].vv("Algorithm") = CanonicalizationString;

			// Hash
			dhash.clear();
			HASH hash2(alg);
			hash2.hash((BYTE*)sps.c_str(), (DWORD)sps.length());
			hash2.get(dhash);
			d2 = XML3::Char2Base64((const char*)dhash.data(), dhash.size(), false);
			ref2["ds:DigestMethod"].vv("Algorithm") = alg2from();
			ref2["ds:DigestValue"].SetContent(d2.c_str());


			auto& ref3 = ds_SignedInfo.AddElement("ds:Reference");
			sprintf_s(d, 1000, "#xmldsig-%s-keyinfo", id1.c_str());
			ref3.vv("URI") = d;
			ref3.vv("Id") = "SignedInfoKeyProperties";

			ref3["ds:Transforms"]["ds:Transform"].vv("Algorithm") = CanonicalizationString;

			// Hash
			dhash.clear();
			HASH hash3(alg);
			hash3.hash((BYTE*)spk.c_str(), (DWORD)spk.length());
			hash3.get(dhash);
			d2 = XML3::Char2Base64((const char*)dhash.data(), dhash.size(), false);
			ref3["ds:DigestMethod"].vv("Algorithm") = alg2from();
			ref3["ds:DigestValue"].SetContent(d2.c_str());

			// Unsigned 
			if (lev >= LEVEL::T)
			{
				auto& xup = xqp.AddElement("xades:UnsignedProperties");
				xup.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
				xup.vv("xmlns:xades141") = "http://uri.etsi.org/01903/v1.4.1#";	
				/*<xades:UnsignedSignatureProperties>
								<xades:SignatureTimeStamp>
									<ds:CanonicalizationMethod Algorithm=CanonicalizationString/>
									<xades:EncapsulatedTimeStamp>*/
				auto& xusp = xup.AddElement("xades:UnsignedSignatureProperties");
				auto& xstt = xusp.AddElement("xades:SignatureTimeStamp");
				xstt["ds:CanonicalizationMethod"].vv("Algorithm") = CanonicalizationString;

				XML3::XMLElement c = "xades:EncapsulatedTimeStamp";
				tscontent = xstt.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(c));

				if (lev >= LEVEL::C)
				{
					auto [xcc1,xcc2a] = XMLAddC(xusp, Certificates, putcert, putcrl);
					if (lev >= LEVEL::X)
					{
						XMLAddX(*this, Params, CanonicalizationString, xusp, ser, xcc1, xcc2a);
						if (lev >= LEVEL::XL)
						{
							XMLAddXL(xusp, Certificates);
						}
					}
				}
			}


		}

		ds_Signature.AddElement(ds_SignedInfo);

		// Value
		string _ds_sv = R"(<ds:SignatureValue></ds:SignatureValue>)";
		XML3::XMLElement sv = _ds_sv.c_str();
		if (Params.ASiC)
		{
			sv.vv("xmlns:asic") = "http://uri.etsi.org/02918/v1.2.1#";
			sv.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
			sv.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";
			sv.vv("xmlns:xsi") = "http://www.w3.org/2001/XMLSchema-instance";
		}
		else
			sv.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";

		sprintf_s(d, 1000, "xmldsig-%s-sigvalue", id1.c_str());
		if (lev != LEVEL::XMLDSIG)
			sv.vv("Id") = d;

		// Remove prefix if necessary 
		if (lev == LEVEL::XMLDSIG)
		{
			remprefix(ds_SignedInfo);
			ds_SignedInfo.SetElementName("SignedInfo");
		}
		string sf = ds_SignedInfo.Serialize(&ser);


		std::vector<char> Sig;
		hr = GetEncryptedHash(sf.data(), (DWORD)sf.size(), Certificates[iCert].cert.cert, Params.HashAlgorithm, Sig);
		string dss = XML3::Char2Base64((const char*)Sig.data(), Sig.size(), false);
		sv.SetContent(dss.c_str());

		if (lev >= LEVEL::T)
		{
			string svs = sv.Serialize(&ser);
			std::vector<char> tsr;
			TimeStamp(Params, (char*)svs.data(), (DWORD)svs.size(), tsr, Params.TSServer.c_str());
			string b = XML3::Char2Base64(tsr.data(), tsr.size(), false);
			tscontent->SetContent(b.c_str());
		}



		ds_Signature.AddElement(sv);
		ds_Signature.AddElement(ki);
		if (lev != LEVEL::XMLDSIG)
		{
			ds_Signature.AddElement(o2);
		}

/*
		if (lev >= LEVEL::A)
		{
			// SignedSignatureProperties 
			CollectionForA.push_back(&xssp);

			// SignedDataObjectProperties 
			CollectionForA.push_back(&xsdop);

			// ds:SignatureValue
			CollectionForA.push_back(&xsdop);


			XMLAddA(xusp, dat, Certificates);
		}
*/

		// Remove namespaces which we put for hashing
		ds_Signature.RemoveDuplicateNamespaces(0);

		x.GetRootElement().AddElement(ds_Signature);
		ser.Canonical = true;

		// Prefix, out
		if (lev == LEVEL::XMLDSIG)
		{
			remprefix(x.GetRootElement());
		}


		string res;
		if (Params.Attached == ATTACHTYPE::DETACHED)
			res = ds_Signature.Serialize(&ser);
		else
			if (Params.Attached == ATTACHTYPE::ENVELOPING)
			{
				for (auto& data : dat)
				{
					auto URIRef = data.ref;
					XML3::XMLElement enveloping = lev == LEVEL::XMLDSIG ? "Object" : "ds:Object";
					enveloping.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
					enveloping.vv("Id") = URIRef;

					XML3::XML x4;
					x4.Parse((char*)data.data, strlen((char*)data.data));

					enveloping.AddElement(x4.GetRootElement());
					ds_Signature.AddElement(enveloping);
				}

				res = ds_Signature.Serialize(&ser);
			}
			else
				res = x.Serialize(&ser);
		auto es = Signature.size();
		Signature.resize(es + res.length());
		memcpy(Signature.data() + es, res.c_str(), res.length());
	}

	if (Certificates.size() > 1)
	{
		string s1 = "<root>";
		string s2 = "</root>";
		Signature.insert(Signature.begin(), s1.begin(), s1.end());
		Signature.insert(Signature.end(), s2.begin(), s2.end());
	}

	return hr;
}

void hd(std::vector<char> d)
{
	using namespace std;
	string e;
	char ee[10];
	for (auto c : d)
	{
		sprintf_s(ee, 10, "%02X", c);
		e += ee;
	}
	MessageBoxA(0, e.c_str(), 0, 0);
}

HRESULT AdES::AddCT(std::vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params)
{
	HRESULT hr = E_FAIL;
	DWORD dflg = 0;
	if (Params.Attached == ATTACHTYPE::DETACHED)
		dflg = CMSG_DETACHED_FLAG;
	DWORD cbEncodedBlob = 0;

	std::vector<char> EH;
	auto hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, dflg, 0, 0, 0, 0);
	if (hMsg)
	{
		if (CryptMsgUpdate(hMsg, (BYTE*)Signature.data(), (DWORD)Signature.size(), TRUE))           // Last call
		{
			// Get the encrypted hash for timestamp
			bool S = true;
			for (DWORD i = 0; i < Certificates.size(); i++)
			{
				if (CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, i, NULL, &cbEncodedBlob))
				{
					EH.resize(cbEncodedBlob);
					if (CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, i, (BYTE*)EH.data(), &cbEncodedBlob))
					{
						EH.resize(cbEncodedBlob);

						std::vector<char> CR;
						auto hrx = TimeStamp(Params, EH.data(), (DWORD)EH.size(), CR, Params.TSServer.c_str());
						if (FAILED(hrx))
						{
							S = false;
							continue;
						}

						if (CR.size())
						{
							CRYPT_ATTRIBUTE cat = { 0 };
							cat.cValue = 1;
							CRYPT_ATTR_BLOB bl;
							bl.cbData = (DWORD)CR.size();
							bl.pbData = (BYTE*)CR.data();
							cat.rgValue = &bl;
							cat.pszObjId = "1.2.840.113549.1.9.16.2.14";
							DWORD aa;
							CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, 0, &aa);
							std::vector<char> enc(aa);
							CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, (BYTE*)enc.data(), &aa);
							enc.resize(aa);

							CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA  ua = { 0 };
							ua.cbSize = sizeof(ua);
							ua.blob.pbData = (BYTE*)enc.data();
							ua.blob.cbData = (DWORD)enc.size();

							ua.dwSignerIndex = i;
							if (!CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &ua))
								S = false;
						}
					}
				}
			}

			if (S)
			{
				if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, NULL, &cbEncodedBlob))       // Size of the returned information
				{
					Signature.resize(cbEncodedBlob);
					if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, (BYTE*)Signature.data(), &cbEncodedBlob))       // Size of the returned information
					{
						Signature.resize(cbEncodedBlob);
						hr = S_OK;
					}
				}
			}
		}
	}
	if (hMsg)
	{
		CryptMsgClose(hMsg);
		hMsg = 0;
	}

	return hr;
}



std::tuple<HRESULT, std::vector<char>, std::vector<char>>  AdES::AddCC(std::vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params)
{
	using namespace std;
	HRESULT hr = E_FAIL;
	DWORD dflg = 0;
	if (Params.Attached == ATTACHTYPE::DETACHED)
		dflg = CMSG_DETACHED_FLAG;
	vector <shared_ptr<std::vector<char>>> mem;
	DWORD cbEncodedBlob = 0;


	std::vector<char> buff3;
	std::vector<char> buff5;
	std::vector<char> full1;
	std::vector<char> full2;

	std::vector<char> EH;
	auto hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, dflg, 0, 0, 0, 0);
	if (hMsg)
	{
		if (CryptMsgUpdate(hMsg, (BYTE*)Signature.data(), (DWORD)Signature.size(), TRUE))           // Last call
		{
			// Get the encrypted hash for timestamp
			bool S = true;
			for (DWORD i = 0; i < Certificates.size(); i++)
			{
				auto& cert = Certificates[i];

				// Complete Refs
				CompleteCertificateRefs* v2 = AddMem<CompleteCertificateRefs>(mem, sizeof(CompleteCertificateRefs));
				v2->list.size = (DWORD)cert.More.size();
				v2->list.count = (DWORD)cert.More.size();
				v2->list.array = AddMem<OtherCertID*>(mem, (int)cert.More.size() * sizeof(OtherCertID*));
				for (size_t i5 = 0; i5 < cert.More.size(); i5++)
				{
					auto& c = cert.More[i5];
					// Hash of the cert
					std::vector<BYTE> dhash;
					HASH hash(BCRYPT_SHA1_ALGORITHM);
					hash.hash(c.cert->pbCertEncoded, c.cert->cbCertEncoded);
					hash.get(dhash);
					BYTE* hashbytes = AddMem<BYTE>(mem, dhash.size());
					memcpy(hashbytes, dhash.data(), dhash.size());

					v2->list.array[i5] = AddMem<OtherCertID>(mem);
					v2->list.array[i5]->otherCertHash.present = OtherHash_PR_sha1Hash;
					v2->list.array[i5]->otherCertHash.choice.sha1Hash.buf = hashbytes;
					v2->list.array[i5]->otherCertHash.choice.sha1Hash.size = (DWORD)dhash.size();
				}
				// Encode it as DER
				auto ec2 = der_encode(&asn_DEF_CompleteCertificateRefs,
					v2, [](const void *buffer, size_t size, void *app_key) ->int
				{
					std::vector<char>* x = (std::vector<char>*)app_key;
					auto es = x->size();
					x->resize(x->size() + size);
					memcpy(x->data() + es, buffer, size);
					return 0;
				}, (void*)&buff3);


				if (true)
				{
					CRYPT_ATTRIBUTE cat = { 0 };
					cat.cValue = 1;
					CRYPT_ATTR_BLOB bl;
					bl.cbData = (DWORD)buff3.size();
					bl.pbData = (BYTE*)buff3.data();
					cat.rgValue = &bl;

					cat.pszObjId = "1.2.840.113549.1.9.16.2.21";
					DWORD aa;
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, 0, &aa);
					std::vector<char> enc(aa);
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, (BYTE*)enc.data(), &aa);
					enc.resize(aa);

					CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA  ua = { 0 };
					ua.cbSize = sizeof(ua);
					ua.blob.pbData = (BYTE*)enc.data();
					ua.blob.cbData = (DWORD)enc.size();

					full1 = enc;
					ua.dwSignerIndex = i;
					if (!CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &ua))
						S = false;
				}

				auto cmss = cert.More.size() + 1;
				CompleteRevocationRefs* v3 = AddMem<CompleteRevocationRefs>(mem, sizeof(CompleteRevocationRefs));
				v3->list.size = (DWORD)cmss; // For more and self
				v3->list.count = (DWORD)cmss; // For more and self
				v3->list.array = AddMem<CrlOcspRef*>(mem, (int)(cmss) * sizeof(CrlOcspRef*));
				for (size_t i4 = 0; i4 < cmss; i4++)
				{
					auto& c = (i4 == 0) ? cert.cert.Crls : cert.More[i4 - 1].Crls;
					DWORD ccount = (DWORD)c.size();
					v3->list.array[i4] = AddMem<CrlOcspRef>(mem);
					v3->list.array[i4]->crlids = AddMem<CRLListID>(mem);
					v3->list.array[i4]->crlids->crls.list.count = (DWORD)c.size();
					v3->list.array[i4]->crlids->crls.list.size = (DWORD)c.size();
					v3->list.array[i4]->crlids->crls.list.array = AddMem<CrlValidatedID*>(mem, ccount * sizeof(CrlValidatedID*));

					for (size_t iii = 0; iii < ccount; iii++)
					{
						auto& crl = c[iii];
						// Hash of the cert
						std::vector<BYTE> dhash;
						HASH hash(BCRYPT_SHA1_ALGORITHM);
						hash.hash(crl->pbCrlEncoded, crl->cbCrlEncoded);
						hash.get(dhash);
						BYTE* hashbytes = AddMem<BYTE>(mem, dhash.size());
						memcpy(hashbytes, dhash.data(), dhash.size());

						v3->list.array[i4]->crlids->crls.list.array[iii] = AddMem<CrlValidatedID>(mem, sizeof(CrlValidatedID));
						v3->list.array[i4]->crlids->crls.list.array[iii]->crlHash.present = OtherHash_PR_sha1Hash;
						v3->list.array[i4]->crlids->crls.list.array[iii]->crlHash.choice.sha1Hash.buf = hashbytes;
						v3->list.array[i4]->crlids->crls.list.array[iii]->crlHash.choice.sha1Hash.size = (DWORD)dhash.size();

					}
				}
				// Encode it as DER
				auto ec3 = der_encode(&asn_DEF_CompleteRevocationRefs,
					v3, [](const void *buffer, size_t size, void *app_key) ->int
				{
					std::vector<char>* x = (std::vector<char>*)app_key;
					auto es = x->size();
					x->resize(x->size() + size);
					memcpy(x->data() + es, buffer, size);
					return 0;
				}, (void*)&buff5);


				if (true)
				{
					CRYPT_ATTRIBUTE cat = { 0 };
					cat.cValue = 1;
					CRYPT_ATTR_BLOB bl;
					bl.cbData = (DWORD)buff5.size();
					bl.pbData = (BYTE*)buff5.data();
					cat.rgValue = &bl;


					cat.pszObjId = "1.2.840.113549.1.9.16.2.22";
					DWORD aa;
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, 0, &aa);
					std::vector<char> enc(aa);
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, (BYTE*)enc.data(), &aa);
					enc.resize(aa);

					CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA  ua = { 0 };
					ua.cbSize = sizeof(ua);
					ua.blob.pbData = (BYTE*)enc.data();
					ua.blob.cbData = (DWORD)enc.size();

					full2 = enc;

					ua.dwSignerIndex = i;
					if (!CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &ua))
						S = false;
				}

			}

			if (S)
			{
				if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, NULL, &cbEncodedBlob))       // Size of the returned information
				{
					Signature.resize(cbEncodedBlob);
					if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, (BYTE*)Signature.data(), &cbEncodedBlob))       // Size of the returned information
					{
						Signature.resize(cbEncodedBlob);
						hr = S_OK;
					}
				}
			}
		}
	}
	if (hMsg)
	{
		CryptMsgClose(hMsg);
		hMsg = 0;
	}

	return make_tuple(hr, full1, full2);
}

HRESULT AdES::AddCX(std::vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& full1, std::vector<char >&full2)
{
	HRESULT hr = E_FAIL;
	DWORD dflg = 0;
	if (Params.Attached == ATTACHTYPE::DETACHED)
		dflg = CMSG_DETACHED_FLAG;
	DWORD cbEncodedBlob = 0;

	std::vector<char> EH;
	auto hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, dflg, 0, 0, 0, 0);
	if (hMsg)
	{
		if (CryptMsgUpdate(hMsg, (BYTE*)Signature.data(), (DWORD)Signature.size(), TRUE))           // Last call
		{
			// Get the encrypted hash for timestamp
			bool S = true;
			for (DWORD i = 0; i < Certificates.size(); i++)
			{
				// cert + rev but without tag-length
				std::vector<char> EH2 = StripASNTagLength(full1);
				std::vector<char> EH3 = StripASNTagLength(full2);
				EH2.insert(EH2.end(), EH3.begin(), EH3.end());

				std::vector<BYTE> dhash;
				HASH hash(BCRYPT_SHA256_ALGORITHM);
				hash.hash((BYTE*)EH2.data(), (DWORD)EH2.size());
				hash.get(dhash);

				std::vector<char> CR;
				auto hrx = TimeStamp(Params, EH2.data(), (DWORD)EH2.size(), CR, Params.TSServer.c_str());
				if (FAILED(hrx))
				{
					S = false;
					continue;
				}
				if (true)
				{
					CRYPT_ATTRIBUTE cat = { 0 };
					cat.cValue = 1;
					CRYPT_ATTR_BLOB bl;
					bl.cbData = (DWORD)CR.size();
					bl.pbData = (BYTE*)CR.data();
					cat.rgValue = &bl;
					cat.pszObjId = "1.2.840.113549.1.9.16.2.26";
					DWORD aa;
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, 0, &aa);
					std::vector<char> enc(aa);
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, (BYTE*)enc.data(), &aa);
					enc.resize(aa);

					CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA  ua = { 0 };
					ua.cbSize = sizeof(ua);
					ua.blob.pbData = (BYTE*)enc.data();
					ua.blob.cbData = (DWORD)enc.size();

					ua.dwSignerIndex = i;
					if (!CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &ua))
						S = false;
				}
			}

			if (S)
			{
				if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, NULL, &cbEncodedBlob))       // Size of the returned information
				{
					Signature.resize(cbEncodedBlob);
					if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, (BYTE*)Signature.data(), &cbEncodedBlob))       // Size of the returned information
					{
						Signature.resize(cbEncodedBlob);
						hr = S_OK;
					}
				}
			}
		}
	}
	if (hMsg)
	{
		CryptMsgClose(hMsg);
		hMsg = 0;
	}

	return hr;
}



HRESULT AdES::AddCXL(std::vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params)
{
	HRESULT hr = E_FAIL;
	DWORD dflg = 0;
	if (Params.Attached == ATTACHTYPE::DETACHED)
		dflg = CMSG_DETACHED_FLAG;
	DWORD cbEncodedBlob = 0;

	std::vector<char> EH;
	auto hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, dflg, 0, 0, 0, 0);
	if (hMsg)
	{
		if (CryptMsgUpdate(hMsg, (BYTE*)Signature.data(), (DWORD)Signature.size(), TRUE))           // Last call
		{
			// Get the encrypted hash for timestamp
			bool S = true;
			for (DWORD i = 0; i < Certificates.size(); i++)
			{
				std::vector<PCCERT_CONTEXT> ve;
				std::vector<PCCRL_CONTEXT> vcrls;
				auto& c = Certificates[i];
				ve.push_back(c.cert.cert);
				for (auto& cc : c.cert.Crls)
				{
					vcrls.push_back(cc);
				}
				for (auto& cc : c.More)
				{
					ve.push_back(cc.cert);
					for (auto& ccc : cc.Crls)
					{
						vcrls.push_back(ccc);
					}
				}
				auto CR = EncodeCertList(ve);
				if (true)
				{
					CRYPT_ATTRIBUTE cat = { 0 };
					cat.cValue = 1;
					CRYPT_ATTR_BLOB bl;
					bl.cbData = (DWORD)CR.size();
					bl.pbData = (BYTE*)CR.data();
					cat.rgValue = &bl;
					cat.pszObjId = "1.2.840.113549.1.9.16.2.23";
					DWORD aa;
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, 0, &aa);
					std::vector<char> enc(aa);
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, (BYTE*)enc.data(), &aa);
					enc.resize(aa);

					CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA  ua = { 0 };
					ua.cbSize = sizeof(ua);
					ua.blob.pbData = (BYTE*)enc.data();
					ua.blob.cbData = (DWORD)enc.size();

					ua.dwSignerIndex = i;
					if (!CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &ua))
						S = false;
				}

				CR = EncodeCRLList(vcrls);
				if (true)
				{
					CRYPT_ATTRIBUTE cat = { 0 };
					cat.cValue = 1;
					CRYPT_ATTR_BLOB bl;
					bl.cbData = (DWORD)CR.size();
					bl.pbData = (BYTE*)CR.data();
					cat.rgValue = &bl;
					cat.pszObjId = "1.2.840.113549.1.9.16.2.24";
					DWORD aa;
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, 0, &aa);
					std::vector<char> enc(aa);
					CryptEncodeObject(MY_ENCODING_TYPE, PKCS_ATTRIBUTE, (void*)&cat, (BYTE*)enc.data(), &aa);
					enc.resize(aa);

					CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA  ua = { 0 };
					ua.cbSize = sizeof(ua);
					ua.blob.pbData = (BYTE*)enc.data();
					ua.blob.cbData = (DWORD)enc.size();

					ua.dwSignerIndex = i;
					if (!CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &ua))
						S = false;
				}
			}

			if (S)
			{
				if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, NULL, &cbEncodedBlob))       // Size of the returned information
				{
					Signature.resize(cbEncodedBlob);
					if (CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, (BYTE*)Signature.data(), &cbEncodedBlob))       // Size of the returned information
					{
						Signature.resize(cbEncodedBlob);
						hr = S_OK;
					}
				}
			}
		}
	}
	if (hMsg)
	{
		CryptMsgClose(hMsg);
		hMsg = 0;
	}

	return hr;
}

#include "pdf.hpp"


HRESULTERROR AdES::PDFCreateDSSObject(const std::vector<CERT>& Certificates, long long objnum, std::vector<std::vector<char>>& r)
{
	if (Certificates.empty())
		return E_INVALIDARG;

	// Get the CRLs
	std::vector<PCCRL_CONTEXT> crls;
	std::vector<PCCERT_CONTEXT> certs;

	for (auto& c : Certificates)
	{
		for (auto& cc : c.cert.Crls)
		{
			crls.push_back(cc);
		}

		for (auto& cc : c.More)
		{
			for (auto& ccc : cc.Crls)
			{
				crls.push_back(ccc);
			}
		}
	}

	for (auto& c : Certificates)
	{
		certs.push_back(c.cert.cert);
		for (auto& cc : c.More)
		{
			certs.push_back(cc.cert);
		}
	}

	if (crls.empty() || certs.empty())
		return E_INVALIDARG;

	/*
	399 0 obj
<</Length 749/Filter/FlateDecode>>stream
	endstream
	endobj

	*/

	std::vector<long long> certobjs;
	for (auto& c : certs)
	{
		std::vector<char> co(1024 * 1024);
		uLong cxs = 1024 * 1024;
		int u = compress((Bytef*)co.data(), &cxs, (Bytef*)c->pbCertEncoded, c->cbCertEncoded);
		if (u != 0)
			return E_FAIL;
		co.resize(cxs);

		PDF::astring g1;
		g1.Format("%llu 0 obj\n<</Length %u/Filter/FlateDecode>>stream\n", objnum, cxs);
		PDF::astring g2;
		g2.Format("\nendstream\nendobj\n");

		std::vector<char> f;
		f.insert(f.end(), g1.begin(), g1.end());
		f.insert(f.end(), co.begin(), co.end());
		f.insert(f.end(), g2.begin(), g2.end());

		r.push_back(f);
		certobjs.push_back(objnum++);
	}


	std::vector<long long> crlobjs;
	for (auto& c : crls)
	{
		std::vector<char> co(1024 * 1024);
		uLong cxs = 1024*1024;
		int u = compress((Bytef*)co.data(), &cxs, (Bytef*)c->pbCrlEncoded, c->cbCrlEncoded);
		if (u != 0)
			return E_FAIL;
		co.resize(cxs);

		PDF::astring g1;
		g1.Format("%llu 0 obj\n<</Length %u/Filter/FlateDecode>>stream\n", objnum,cxs);
		PDF::astring g2;
		g2.Format("\nendstream\nendobj\n");

		std::vector<char> f;
		f.insert(f.end(), g1.begin(), g1.end());
		f.insert(f.end(), co.begin(), co.end());
		f.insert(f.end(), g2.begin(), g2.end());

		r.push_back(f);
		crlobjs.push_back(objnum++);
	}

	// Create the Cert index
	long long certobj = objnum;
	if (true)
	{
		PDF::astring g1;
		g1.Format("%llu 0 obj\n[", objnum);
		for (auto& c : certobjs)
		{
			PDF::astring g1a;
			g1a.Format("%llu 0 R ", c);
			g1 += g1a;
		}
		g1 += "]\nendobj\n";
		std::vector<char> f1;
		f1.insert(f1.end(), g1.begin(), g1.end());
		r.push_back(f1);
		objnum++;
	}

	// Create the CRL index
	long long crlobj = objnum;
	if (true)
	{
		PDF::astring g1;
		g1.Format("%llu 0 obj\n[", objnum);
		for (auto& c : crlobjs)
		{
			PDF::astring g1a;
			g1a.Format("%llu 0 R ", c);
			g1 += g1a;
		}
		g1 += "]\nendobj\n";
		std::vector<char> f1;
		f1.insert(f1.end(), g1.begin(), g1.end());
		r.push_back(f1);
		objnum++;
	}

	// Create the DSS object
	long long dssobj = objnum;
	if (true)
	{
		PDF::astring g1;
		g1.Format("%llu 0 obj\n<</Type/DSS/Certs %llu 0 R/CRLs %llu 0 R>>\nendobj\n", objnum,certobj,crlobj);
		std::vector<char> f1;
		f1.insert(f1.end(), g1.begin(), g1.end());
		r.push_back(f1);
		objnum++;
	}

	return S_OK;
}


HRESULT AdES::GreekVerifyTimestamp(PCCERT_CONTEXT a, PCRYPT_TIMESTAMP_CONTEXT tc, GREEKRESULTS& r)
{
	HRESULT rx = E_FAIL;
	if (!a || !tc)
		return rx;

	// The certificate
	PCERT_EXTENSION policyExt = CertFindExtension(szOID_ENHANCED_KEY_USAGE,
		a->pCertInfo->cExtension, a->pCertInfo->rgExtension);
	if (!policyExt)
		return rx;
	CERT_ENHKEY_USAGE* ku = 0;
	DWORD size;

	if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE,
		policyExt->Value.pbData, policyExt->Value.cbData,
		CRYPT_DECODE_ALLOC_FLAG, NULL, &ku, &size))
	{
		if (ku->rgpszUsageIdentifier && strcmp(*ku->rgpszUsageIdentifier, "1.3.6.1.5.5.7.3.8") == 0)
		{
			r.TSThere = 1;
			std::vector<wchar_t> name(1000);
			CertGetNameString(a,
				CERT_NAME_SIMPLE_DISPLAY_TYPE,
				CERT_NAME_ISSUER_FLAG,
				NULL,
				name.data(),1000);
			wchar_t* a1 = name.data();
			if (wcscmp(a1, L"HPARCA Time Stamping Services CA") == 0)
			{
				// Policy
				if (strcmp(tc->pTimeStamp->pszTSAPolicyId,"1.3.6.1.4.1.601.10.3.1") == 0)
					r.TSThere = 2;
			}
		}
		LocalFree(ku);
	}
}

HRESULT AdES::GreekVerifyCertificate(PCCERT_CONTEXT a, const char* sig, DWORD sigsize, GREEKRESULTS& r)
{
	using namespace std;
	HRESULT rx = E_FAIL;
	if (!a)
		return rx;
	r.Type = 0;
	PCERT_EXTENSION policyExt = CertFindExtension(szOID_CERT_POLICIES,
		a->pCertInfo->cExtension, a->pCertInfo->rgExtension);
	if (!policyExt)
		return rx;
	CERT_POLICIES_INFO* policies = 0;
	DWORD size;

	if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT_POLICIES,
		policyExt->Value.pbData, policyExt->Value.cbData,
		CRYPT_DECODE_ALLOC_FLAG, NULL, &policies, &size))
	{
		for (DWORD i = 0; i < policies->cPolicyInfo; i++)
		{
			auto& ji = policies->rgPolicyInfo[i];
			if (string(ji.pszPolicyIdentifier) == string("1.2.300.0.110001.1.7.1.1.1"))
			{
				r.Type = 2;
				rx = S_OK;
			}
			if (string(ji.pszPolicyIdentifier) == string("1.2.300.0.110001.1.7.1.1.3"))
			{
				r.Type = 1;
				rx = S_OK;
			}
			for (DWORD j = 0; j < ji.cPolicyQualifier; j++)
			{
				auto& p = ji.rgPolicyQualifier[j];
				//							MessageBeep(0);
			}
		}
		if (policies)
			LocalFree(policies);
	}

	// Check the timestamp
	r.Level = 0;
	PCCERT_CONTEXT ce = 0;
	PCRYPT_TIMESTAMP_CONTEXT ptc = 0;
	auto hr2 = VerifyT(sig, sigsize, &ce, false, 0, 0, &ptc);
	if (SUCCEEDED(hr2))
	{
		r.Level = (int)LEVEL::T;
		GreekVerifyTimestamp(ce, ptc, r);
		if (ptc)
			CryptMemFree(ptc);
		if (ce)
			CertFreeCertificateContext(ce);
	}

	return rx;
}

HRESULTERROR AdES::PDFVerify(const char* d, DWORD sz, std::vector<PDFVERIFY>& VerifyX)
{
	AdES::SIGNPARAMETERS Params;
	std::vector<AdES::CERT> Certs;
	LEVEL levx = LEVEL::CMS;
	std::vector<char> res;
	return PDFSign(levx, d, sz, Certs, Params, res, &VerifyX);
}

HRESULTERROR AdES::PDFSign(LEVEL levx, const char* d, DWORD sz, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& res,std::vector<PDFVERIFY>* VerifyX)
{
	using namespace std;
	PDF::PDF pdf;
	auto herr = pdf.Parse2(d, sz);
	if (FAILED(herr))
		return herr;

	// We have parsed it...
	if (pdf.docs.empty())
		return HRESULTERROR(E_FAIL,"No documents inside PDF");

	auto rootobject = pdf.findobject(pdf.root());
	if (!rootobject)
		return HRESULTERROR(E_FAIL, "No root object");
	auto infoobject = pdf.findobject(pdf.info());
	auto lastpages = pdf.findname(rootobject, "Pages");
	if (lastpages == 0)
		return HRESULTERROR(E_FAIL, "No Pages object");
	auto iiPage = atoll(lastpages->Value.c_str());
	auto PageObject = pdf.findobject(iiPage);
	if (!PageObject)
		return HRESULTERROR(E_FAIL, "No Page Object");
	auto lastkids = pdf.findname(PageObject, "Kids");
	if (lastkids == 0)
		return HRESULTERROR(E_FAIL, "No Kids in Page");

	long long lastsize = pdf.docs[0].size();
	auto lastID = pdf.docs[0].GetID();

	// Count from all revisions
	long long Count = 0;
	std::vector<PDF::OBJECT*> FoundCounts;
	for (auto& doc : pdf.docs)
	{
		auto rn = doc.root();
		auto ro = doc.findobject(rn);
		if (!ro)
			continue;
		auto pobj = doc.findname(&ro->content, "Pages");
		if (!pobj)
			continue;

		int iPg = atoi(pobj->Value.c_str());
		auto p2obj = pdf.findobject(iPg);
		if (!p2obj)
			continue;

		if (std::find(FoundCounts.begin(), FoundCounts.end(), p2obj) != FoundCounts.end())
			continue;

		FoundCounts.push_back(p2obj);
		auto count = doc.findname(&p2obj->content, "Count");
		if (count)
		{
			Count += atoll(count->Value.c_str());
		}
	}
	if (Count == 0)
		Count = 1;

	string firstref = "";
	if (lastkids->Contents.size() >= 1 && lastkids->Contents.front().Type == PDF::INXTYPE::TYPE_ARRAY)
	{
		auto spl = split(lastkids->Contents.front().Value, ' ');
		while (!spl.empty())
		{
			if (spl[0] == "")
			{
				spl.erase(spl.begin());
				continue;
			}
			firstref = spl[0];
			break;
		}
	}
	else
	{
		auto spl = split(lastkids->Value, ' ');
		while (!spl.empty())
		{
			if (spl[0] == "")
			{
				spl.erase(spl.begin());
				continue;
			}
			firstref = spl[0];
			break;
		}
	}

	long long iFirstRef = atoll(firstref.c_str());
	if (iFirstRef == 0)
		return HRESULTERROR(E_FAIL, "No first reference found");
	auto RefObject = pdf.findobject(iFirstRef);
	if (!RefObject)
		return HRESULTERROR(E_FAIL, "No RefObject");

	// Serialization of this reference
	if (RefObject->content.Type != PDF::INXTYPE::TYPE_DIC)
		return HRESULTERROR(E_FAIL, "No contect in RefObject");

//	auto lastcnt = pdf.findname(RefObject, "Contents");
//	if (lastcnt == 0)
	//	return E_UNEXPECTED;

	auto& last = pdf.docs[0];
	unsigned long long mxd = pdf.maxobjectnum;// +1;
	//int iContents = atoll(lastcnt->Value.c_str());


	bool InRL = false;
	std::vector<char> to_sign;
	char* ps = to_sign.data();
	char* ps2 = res.data();
	to_sign.resize(sz);
	memcpy(to_sign.data(), d, sz);
	res.resize(sz); 
	memcpy(res.data(), d, sz);

	//			int iRoot = mxd + 1;
	//			int iPages = mxd + 2;
	//			int iPage = mxd + 3;
	//			int iSignature = mxd + 6;
	//			int iXOBject = mxd + 7;
	//			int iDescribeSignature = mxd + 8;
	//			int iFont = mxd + 9;
	//			int iFont2 = mxd + 10;
	//			int iProducer = mxd + 11;

	
	auto iRoot = mxd + 1;
	auto iPages = mxd + 2;
	auto iPage = mxd + 3;
	auto iSignature = mxd + 4;
	auto iXOBject = mxd + 5;
	auto iDescribeSignature = mxd + 6;
	auto iFont = mxd + 7;
	auto iFont2 = mxd + 8;
	auto iProducer = mxd + 9;
	auto iObjectXref = mxd + 10;
	auto iVis1 = mxd + 11;
	auto iDSS = mxd + 15;

	bool SwitchReferences =  true;

	/*

	We will switch:
		Root Object
		Info Object
		Page Object
		1rst Ref Object
	
	*/

	if (SwitchReferences)
	{
		iRoot = rootobject->num;
		if (infoobject)
			iProducer = infoobject->num;
		else
			iProducer = mxd + 6;
		iPages = PageObject->num;
		iPage = RefObject->num;

		iSignature = mxd + 1;
		iXOBject = mxd + 2;
		iDescribeSignature = mxd + 3;
		iFont = mxd + 4;
		iFont2 = mxd + 5;
		iObjectXref = mxd + 6;
		iVis1 = mxd + 10;
		iDSS = mxd + 11;
	}


	if (Params.pdfparams.Visible.t.empty())
		iDSS -= 4;

	std::vector<char> pageser;
	auto pg = *PageObject;
	for (auto cc = pg.content.Contents.begin(); cc != pg.content.Contents.end(); cc++)
	{
		if (cc->Name.trim() == string("Kids"))
		{
			PDF::astring fx;
			auto v = cc->Contents.front().Value;
			fx.Format("%llu 0 R", iFirstRef);
			auto fou = v.find(fx.c_str(), 0);
			v.erase(fou, fx.length());
			fx.Format("%llu 0 R", iPage);
			if (v[0] != ' ')
				fx.Format("%llu 0 R ", iPage);
			v.insert(0, fx.c_str());
			//pg.content.Contents.erase(cc)
			cc->Contents.front().Value = v;
		}
		if (cc->Name.trim() == string("Count"))
		{
			PDF::astring fx;
			fx.Format("%llu", Count);
			//pg.content.Contents.erase(cc)
			cc->Value = fx;
		}

	}
	pg.content.Serialize(pageser);
	pageser.resize(pageser.size() + 1);



	PDF::INX annots;
	annots.Type = PDF::INXTYPE::TYPE_NAME;
	annots.Name = "Annots";
	PDF::INX annotsr;
	annotsr.Type = PDF::INXTYPE::TYPE_ARRAY;

	// Find font if defined
	int HelvFound = 0;

	HelvFound = 0;

	//* Found Helvetica inside
	if (HelvFound)
	{
		iFont = 0;
		iProducer--;
	}

	// Current Anotations
	long long current_annot_idx = 0;
	auto current_annot = pdf.findname(RefObject, "Annots",&current_annot_idx);

	PDF::astring annot_string;
	annot_string.Format(" %llu 0 R", iDescribeSignature);
	annotsr.Value = annot_string;
	annots.Contents.push_back(annotsr);

	PDF::astring AnnotFinal;
	long long CountExistingSignatures = 0;
	if (current_annot == 0)
	{
		if (VerifyX)
			return HRESULTERROR(E_FAIL, "No Signature found");

		RefObject->content.Contents.push_back(annots);
		AnnotFinal = annot_string;
	}
	else
	{

		if (VerifyX)
		{
			// We verify the signature
			for (auto& annot : current_annot->Contents)
			{
				if (annot.Type != PDF::INXTYPE::TYPE_ARRAY)
				{
					PDFVERIFY pv;
					pv.S = HRESULTERROR(E_FAIL, "No Signature found");

					VerifyX->push_back(pv);
					continue;
				}


				// Check values, may be obj 0 R obj 0 R etc
				std::stringstream stream(annot.Value);
				std::vector<unsigned long long> ObjectsToLook;
				for(int jji = 0 ;jji < 3 ;jji++) {
					long long n = 0;
					string f;
					if (jji == 2)
						stream >> f;
					else
						stream >> n;
					if (!stream)
						break;
					if (n != 0)
						ObjectsToLook.push_back(n);
					if (jji == 2)
						jji = 0;
				}

				for (auto& ObjectToLook : ObjectsToLook)
				{
					PDFVERIFY pv;
					pv.S = HRESULTERROR(E_FAIL, "No Signature found");


					long long RefSigObj = ObjectToLook;
					auto* obj = pdf.findobject(RefSigObj);
					if (!obj)
					{
						VerifyX->push_back(pv);
						continue;
					}
					if (obj->content.Type != PDF::INXTYPE::TYPE_DIC)
					{
						VerifyX->push_back(pv);
						continue;
					}

					// We find the /V
					std::vector<long long>  br;
					std::vector<char> sig;
					unsigned long long SigStartsAt = 0;
					for (auto& cc : obj->content.Contents)
					{
						if (cc.Type == PDF::INXTYPE::TYPE_NAME)
						{
							if (cc.Name == "V")
							{
								long long iSig = atoll(cc.Value.c_str());
								auto* obj2 = pdf.findobject(iSig);
								if (!obj2)
									break;
								if (obj2->content.Type != PDF::INXTYPE::TYPE_DIC)
									break;
								// Find ByteRange and Content
								for (auto& cc2 : obj2->content.Contents)
								{
									if (cc2.Type == PDF::INXTYPE::TYPE_NAME)
									{
										if (cc2.Name == "Contents")
										{
											SigStartsAt = cc2.pp + 10 + obj2->p; // To add /Contents stuff
											for (unsigned long long i = 1; i < cc2.Value.length() - 1; i += 2)
											{
												std::string byteString = cc2.Value.substr(i, 2);
												char byte = (char)strtol(byteString.c_str(), NULL, 16);
												sig.push_back(byte);
											}
										}
										if (cc2.Name == "ByteRange")
										{
											if (cc2.Contents.size() != 1)
												break;
											auto co = cc2.Contents.begin();
											if (co->Type != PDF::INXTYPE::TYPE_ARRAY)
												break;

											std::stringstream stream(co->Value);
											while (1) {
												long long n = 0;
												stream >> n;
												if (!stream)
													break;
												br.push_back(n);
											}
										}
									}
								}
							}
						}
					}




					if (br.size() != 4 || sig.empty())
					{
						//VerifyX->push_back(pv);
						continue;
					}
					std::vector<char> dx;
					dx.resize(br[1] + br[3]);
					memcpy(dx.data(), d + br[0], br[1]);
					memcpy(dx.data() + br[1], d + br[2], br[3]);
					pv.S = Verify(sig.data(), sig.size(), pv.l, dx.data(), dx.size(), 0, &pv.Certs, &pv.vr, true);
					pv.dx = dx;
					pv.sig = sig;
					pv.Full = false;
					if (br[0] == 0)
					{
						if (br[1] == SigStartsAt)
						{
							pv.Full = true;
						}
					}
					VerifyX->push_back(pv);
				}
			}
			return S_OK;
		}

		current_annot->Contents.front().Value += annot_string;
		auto spl = split(current_annot->Contents.front().Value, ' ');
		CountExistingSignatures = (long long )(spl.size() / 3) - 1; // e.g. If 2 signatures, count is 6
		AnnotFinal = current_annot->Contents.front().Value;
	}


	std::vector<char> strref;
	auto refp = pdf.findname(RefObject, "Parent");
	// iPages in Parent
	refp->Value.Format("%llu 0 R", iPages);

	if (!Params.pdfparams.Visible.t.empty())
	{
		auto refc = pdf.findname(RefObject, "Contents");
		if (!refc)
			return HRESULTERROR(E_FAIL, "No contents in first page");
		if (refc->Type == PDF::INXTYPE::TYPE_NAME)
		{
			// Simple name, create array
			PDF::astring vx;
			vx.Format("[%llu 0 R %u 0 R]", iVis1,atoi(refc->Value.c_str()));
			refc->Value = vx;
		}
		else
		{
			// Already array
			// tbd
			return HRESULTERROR(E_FAIL, "Contents in first page is array");
		}

/*		// Also push the reference to our new font reousrce
		PDF::INX rr2;
		rr2.Type = PDF::INXTYPE::TYPE_NAME;
		rr2.Name = "Resources";
		PDF::astring rr2s;
		rr2s.Format(" %llu 0 R", iVis1 - 3);
		rr2.Value = rr2s;
		RefObject->content.Contents.push_back(rr2);
*/
		PDF::OBJECT obj;
	//	refc->Contents.push_back();



	}
	RefObject->content.Serialize(strref);
	strref.resize(strref.size() + 1);

	// A Test
/*	char* a55 = "<</Type/Page/Parent 2 0 R/Resources<</Font<</F1 4 0 R/FAdESFont 14 0 R>>>>/Contents [15 0 R 5 0 R]/Annots[8 0 R]>>";
	strref.resize(strlen(a55) + 1);
	strcpy_s(strref.data(), strref.size() + 1, a55);
	*/

	map<unsigned long long, unsigned long long> xrefs;

	PDF::AddCh(to_sign, "\n");
	PDF::AddCh(res, "\n");
	PDF::astring vSignatureDescriptor;


	if (!Params.pdfparams.Visible.t.empty())
	{
		vSignatureDescriptor.Format("%llu 0 obj\n<</F 132/Type/Annot/Subtype/Widget/Rect[%i %i %i %i]/FT/Sig/DR<<>>/T(Signature%llu)/V %llu 0 R/P %llu 0 R/AP<</N %llu 0 R>>>>\nendobj\n", iDescribeSignature, (int)Params.pdfparams.Visible.left, (int)Params.pdfparams.Visible.top - 2, (int)Params.pdfparams.Visible.left + (int)Params.pdfparams.Visible.wi, (int)Params.pdfparams.Visible.top + (int)Params.pdfparams.Visible.fs + 2, CountExistingSignatures + 1, iSignature, iPage, iXOBject);
	}
	else
		vSignatureDescriptor.Format("%llu 0 obj\n<</F 132/Type/Annot/Subtype/Widget/Rect[0 0 0 0]/FT/Sig/DR<<>>/T(Signature%llu)/V %llu 0 R/P %llu 0 R/AP<</N %llu 0 R>>>>\nendobj\n", iDescribeSignature, CountExistingSignatures + 1, iSignature, iPage, iXOBject);


	xrefs[iDescribeSignature] = to_sign.size();
	AddCh(to_sign, vSignatureDescriptor);
	AddCh(res, vSignatureDescriptor);
	
	PDF::astring vSignature;
	if (InRL)
		vSignature.Format("%llu 0 obj\n<</Contents <", iSignature);
	else
		vSignature.Format("%llu 0 obj\n<</Contents ", iSignature);
	xrefs[iSignature] = to_sign.size();
	PDF::AddCh(to_sign, vSignature);
	PDF::AddCh(res, vSignature);

	unsigned long long u1 = to_sign.size();

	string vs;
	long long de = 30000;
	if (!InRL)
		vs += "<";
	for (int i = 0; i < de; i++)
		vs += "00";
	long long ures = res.size();
	if (!InRL)
		vs += ">";
	PDF::AddCh(res, vs);


	string de3 = "adbe.pkcs7.detached";
	if (levx != AdES::LEVEL::CMS)
			de3 = "ETSI.CAdES.detached";

	
	PDF::astring dd;
	SYSTEMTIME sT;
	GetSystemTime(&sT);
	dd.Format("%04u%02u%02u%02u%02u%02u+00'00'", sT.wYear, sT.wMonth, sT.wDay, sT.wHour, sT.wMinute, sT.wSecond);

	string vafter;

	PDF::astring vSignatureAfter;
	PDF::astring vRoot;
	PDF::astring vFont;
	PDF::astring vFont2;
	PDF::astring vVis1;
	PDF::astring vVisA1;
	PDF::astring vVisA2;
	PDF::astring vVisA3;
	//	PDF::astring v7, v7b;
	PDF::astring v71, v73;
	std::vector<char> v72;

	PDF::astring vProducer;
	PDF::astring vPage;
	PDF::astring vPages;
	PDF::astring vend;
	PDF::astring xrf;
	PDF::astring trl;
	PDF::astring sxref;
	vend += "%%EOF\x0a";

	PDF::astring extrainsign;
	if (Params.pdfparams.Name.length())
	{
		PDF::astring e;
		Params.pdfparams.ClearPars(Params.pdfparams.Name);
		e.Format("/Name(%s)", Params.pdfparams.Name.c_str());
		extrainsign += e;
	}
	if (Params.pdfparams.Contact.length())
	{
		PDF::astring e;
		Params.pdfparams.ClearPars(Params.pdfparams.Contact);
		e.Format("/ContactInfo(%s)", Params.pdfparams.Contact.c_str());
		extrainsign += e;
	}
	if (Params.pdfparams.Reason.length() && Params.commitmentTypeOid == string(""))
	{
		PDF::astring e;
		Params.pdfparams.ClearPars(Params.pdfparams.Reason);
		e.Format("/Reason(%s)", Params.pdfparams.Reason.c_str());
		extrainsign += e;
	}
	if (Params.pdfparams.Location.length())
	{
		PDF::astring e;
		Params.pdfparams.ClearPars(Params.pdfparams.Location);
		e.Format("/Location(%s)", Params.pdfparams.Location.c_str());
		extrainsign += e;
	}

	if (!InRL)
		vSignatureAfter.Format("/Type/Sig/SubFilter/%s%s/M(D:%s)/ByteRange [0 %llu %llu %03llu]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), extrainsign.c_str(), dd.c_str(), (unsigned long long)u1, (unsigned long long)(u1 + vs.length()), (unsigned long long)0LL);
	else
		vSignatureAfter.Format(">/Type/Sig/SubFilter/%s%s/M(D:%s)/ByteRange [0 %llu %llu %03llu]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), extrainsign.c_str(), dd.c_str(), (unsigned long long) u1, (unsigned long long)(u1 + vs.length()), (unsigned long long)0LL);
	vafter += vSignatureAfter;
	if (!HelvFound)
	{
		vFont.Format("%llu 0 obj\n<</BaseFont/Helvetica/Type/Font/Subtype/Type1/Encoding/WinAnsiEncoding/Name/Helv>>\nendobj\n", iFont);
		xrefs[iFont] = vafter.size() + res.size() + 1;
		vafter += vFont;
	}
	vFont2.Format("%llu 0 obj\n<</BaseFont/ZapfDingbats/Type/Font/Subtype/Type1/Name/ZaDb>>\nendobj\n", iFont2);
	xrefs[iFont2] = vafter.size() + res.size() + 1;
	vafter += vFont2;

	if (!Params.pdfparams.Visible.t.empty())
	{

		// Auto
		if (Params.pdfparams.Visible.t == "auto" && Certificates.size() > 0)
		{
			std::vector<char> di(1000);
			CertGetNameStringA(
				Certificates[0].cert.cert,
				CERT_NAME_SIMPLE_DISPLAY_TYPE,
				0,
				NULL,
				di.data(),
				1000);
			if (!strlen(di.data()))
				Params.pdfparams.Visible.t = "PAdES Signature";
			else
			{
				Params.pdfparams.Visible.t = "PAdES Signature: "; 
				Params.pdfparams.Visible.t  += di.data();
			}

			// Find Width
		}


		// Create the 3 entries before iVis1
		vVisA1.Format("%llu 0 obj<</Font %llu 0 R>>\nendobj\n", iVis1 - 3, iVis1 - 2);
		xrefs[iVis1 - 3] = vafter.size() + res.size() + 1;
		vafter += vVisA1;

		vVisA2.Format("%llu 0 obj<</FAdESFont %llu 0 R>>\nendobj\n", iVis1 - 2, iVis1 - 1);
		xrefs[iVis1 - 2] = vafter.size() + res.size() + 1;
		vafter += vVisA2;

		vVisA3.Format("%llu 0 obj<</Type /Font /Subtype /Type1 /BaseFont /Helvetica>>\nendobj\n", iVis1 - 1);
		xrefs[iVis1 - 1] = vafter.size() + res.size() + 1;
		vafter += vVisA3;

		PDF::astring vv1;
		vv1.Format("BT\n%i %i TD\n/F1 %i Tf\n(%s) Tj\nET\n", Params.pdfparams.Visible.left, Params.pdfparams.Visible.top, Params.pdfparams.Visible.fs,Params.pdfparams.Visible.t.c_str());
		long long lele = vv1.length();
		vVis1.Format("%llu 0 obj\n<</Length %llu>>stream\n%s\nendstream\nendobj\n", iVis1, lele,vv1.c_str());
		xrefs[iVis1] = vafter.size() + res.size() + 1;
		vafter += vVis1;
	}

	v71.Format("%llu 0 obj\n<</Type/XObject/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>>/Subtype/Form/BBox[0 0 0 0]/Matrix [1 0 0 1 0 0]/Length 8/FormType 1/Filter/FlateDecode>>stream\n", iXOBject);
	v72.resize(8); v72[0] = 0x78; v72[1] = 0x9C; v72[2] = 0x03; v72[7] = 0x1;
	v73.Format("\nendstream\nendobj\n");
	vafter += v71;
	vafter.insert(vafter.end(), v72.begin(), v72.end());
	vafter += v73;

	//vPage.Format("%llu 0 obj\n<</Parent %llu 0 R/Contents %llu 0 R/Type/Page/Resources<</Font<</Helv %llu 0 R>>>>/MediaBox[0 0 200 200]/Annots[%llu 0 R]>>\nendobj\n", iPage, iPages, iContents, iFont, iDescribeSignature);
	vPage.Format("%llu 0 obj\n%s\r\nendobj\r\n", iPage, strref.data());
	xrefs[iPage] = vafter.size() + res.size() + 1;
	vafter += vPage;
//	vPages.Format("%llu 0 obj\n<</Type/Pages/Count %llu/Kids[%llu 0 R]>>\nendobj\n", iPages,Count, iPage);
	vPages.Format("%llu 0 obj\n%s\r\nendobj\r\n", iPages, pageser.data());
	xrefs[iPages] = vafter.size() + res.size() + 1;
	vafter += vPages;


	// Build DSS if level > XL
	std::vector<std::vector<char>> dss;
	if (levx >= LEVEL::XL)
		PDFCreateDSSObject(Certificates, iDSS,dss);

	// Use the same rootobject
	auto r2 = *rootobject;
	std::vector<char> r2ser;
	if (r2.content.Type == PDF::INXTYPE::TYPE_DIC)
	{
		PDF::astring acro;
		acro.Format("/AcroForm<</Fields[%s]/DR<</Font<</Helv %llu 0 R/ZaDb %llu 0 R>>>>/DA(/Helv 0 Tf 0 g )/SigFlags 3>>", AnnotFinal.c_str(), iFont, iFont2, iPages);
		PDF::OBJECT obj;
		obj.Parse2(0, acro.c_str(), true);
		r2.content.Contents.push_front(obj.content);

		if (!dss.empty())
		{
			PDF::astring dsso;
			dsso.Format("/DSS %llu 0 R", (unsigned long long)( iDSS + dss.size() - 1));
			PDF::OBJECT obj2;
			obj2.Parse2(0, dsso.c_str(), true);
			r2.content.Contents.push_front(obj2.content);
		}
		
		r2.content.Serialize(r2ser);
	}

	if (r2ser.size())
	{
		r2ser.resize(r2ser.size() + 1);
		vRoot.Format("%llu 0 obj\n%s\nendobj\n",iRoot,r2ser.data());

	}
	else
	{
		if (!HelvFound)
			vRoot.Format("%llu 0 obj\n<</Type/Catalog/AcroForm<</Fields[%s]/DR<</Font<</Helv %llu 0 R/ZaDb %llu 0 R>>>>/DA(/Helv 0 Tf 0 g )/SigFlags 3>>/Pages %llu 0 R>>\nendobj\n", iRoot, AnnotFinal.c_str(), iFont, iFont2, iPages);
		else
			vRoot.Format("%llu 0 obj\n<</Type/Catalog/AcroForm<</Fields[%s]/DR<</Font<</Helv %llu 0 R/ZaDb %llu 0 R>>>>/DA(/Helv 0 Tf 0 g )/SigFlags 3>>/Pages %llu 0 R>>\nendobj\n", iRoot, AnnotFinal.c_str(), iFont, iFont2, iPages);
	}

	xrefs[iRoot] = vafter.size() + res.size() + 1;
	vafter += vRoot;
	vProducer.Format("%llu 0 obj\n<</Producer(AdES Tools https://www.turboirc.com)/ModDate(D:%s)>>\nendobj\n", iProducer,dd.c_str());
	xrefs[iProducer] = vafter.size() + res.size() + 1;
	vafter += vProducer;

	// Dss if there
	if (!dss.empty())
	{
		for (long long i = 0; i < dss.size(); i++)
		{
			auto& d = dss[i];
			std::vector<char> vDss;
			vDss.insert(vDss.end(), d.begin(), d.end());

			xrefs[iDSS + i] = vafter.size() + res.size() + 1;
			vafter.insert(vafter.end(), vDss.begin(), vDss.end());
		}
	}

	// build xref
	unsigned long long xrefpos = vafter.size() + res.size() + 1;

	// Build xrefs
	std::vector<unsigned long long> xrint = { iRoot ,iPages, iPage, iSignature, iXOBject, iDescribeSignature, iFont, iFont2,iProducer };
	if (HelvFound)
		xrint = { iRoot ,iPages, iPage, iSignature, iXOBject, iDescribeSignature, iProducer };

	if (!Params.pdfparams.Visible.t.empty())
	{
		xrint.push_back(iVis1 - 3);
		xrint.push_back(iVis1 - 2);
		xrint.push_back(iVis1 - 1);
		xrint.push_back(iVis1);
	}

	for (long long t = 0 ; t < dss.size() ; t++)
	{
		xrint.push_back(iDSS + t);
	}


	bool XRefObject = false;
	if (pdf.XRefAsObject)
		XRefObject = true;
	if (XRefObject)
	{
		xrint.push_back(iObjectXref);
		xrefs[iObjectXref] = xrefpos;
	}

	// Play with ID
	string id1;
	string id2;
	if (lastID != 0 && lastID->Contents.size() == 1 && lastID->Contents.front().Type == PDF::INXTYPE::TYPE_ARRAY)
	{
		string& val = lastID->Contents.front().Value;
		for (long long j = 0;; j++)
		{
			if (val[j] == '<')
				continue;
			if (val[j] == '>')
				break;
			id1 += val[j];
		}
	}
	else
	{
		// Create a new
		std::vector<char> b1(16);
		BCryptGenRandom(NULL, (BYTE*)b1.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		id1 = PDF::BinToHex((unsigned char*)b1.data(), 16);
	}
	std::vector<char> b2(16);
	BCryptGenRandom(NULL, (BYTE*)b2.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	id2 = PDF::BinToHex((unsigned char*)b2.data(), 16);


	// xref format if object:
	// <</Type/XRef/W[x y z]/Root x 0 R/Prev x/ID [<x,y>]/Length x/Info x 0 R/Size x/Filter/FlateDecode>>stream...endstream
	// Stream is
	// (No PNG Prediction)
	// Type (0 or 1)
	// Index (num)
	// Offset (num)
	// CRC at end
	std::vector<char> uncompressedxref;
	std::vector<char> compressedxref;

	xrint.insert(xrint.begin(), 0);
	map<long long, long long> need;
	if (SwitchReferences)
	{
		std::sort(xrint.begin(), xrint.end());

		unsigned long long i = 0;
		need[0] = 1;
		
		auto prev = (--need.end());
		for (auto s : xrint)
		{
			if (s == (i + 1))
			{
				prev->second++;
				i++;
				continue;
			}
			i = s;
			need[i] = 1;
			prev = (--need.end());
		}

		xrf.Format("xref\n");
/*		if (need[0] > 0)
		{
			PDF::astring xg;
			xg.Format("%llu %llu\n", 0, need[0]);
			xrf += xg;
		}
*/
		for (auto s : xrint)
		{
			PDF::astring xg;
			auto j = xrefs[s];
			if (need[s] > 0)
			{
				xg.Format("%llu %llu\n", s,need[s]);
				xrf += xg;
			}
			if (j == 0)
			{
				xg.Format("%010llu 65535 f \n", j);

				std::vector<char> bx(7);
				bx[0] = 0;
				unsigned long b = (unsigned long)j;
				memcpy(bx.data() + 1, &b, 4);
				unsigned short c = 0xFFFF;
				memcpy(bx.data() + 5, &c, 2);
				uncompressedxref.insert(uncompressedxref.end(),bx.begin(),bx.end());

			}
			else
			{
				xg.Format("%010llu 00000 n \n", j);

				std::vector<char> bx(7);
				bx[0] = 1;
				unsigned long b = (unsigned long)j;
				b = _byteswap_ulong(b);
				memcpy(bx.data() + 1, &b, 4);
				unsigned short c = 0;
				memcpy(bx.data() + 5, &c, 2);
				uncompressedxref.insert(uncompressedxref.end(), bx.begin(), bx.end());
			}
			xrf += xg;
		}
	}
	else
	{
		xrf.Format("xref\n%llu %llu\n", iRoot,(unsigned long long) xrint.size());
		for (auto s : xrint)
		{
			PDF::astring xg;
			auto j = xrefs[s];
			if (j != 0)
				xg.Format("%010llu 00000 n \n", j);
			else
				xg.Format("%010llu 00000 f \n", 0LL);
			xrf += xg;
		}
	}

	compressedxref.resize(uncompressedxref.size());
	uLong cxs = uncompressedxref.size();
	compress((Bytef*)compressedxref.data(), &cxs, (Bytef*)uncompressedxref.data(), uncompressedxref.size());


	std::vector<char> uxref;
	if (XRefObject)
	{
		PDF::astring objectxrefidx = "Index [";
		for (auto s : xrint)
		{
			PDF::astring xg;
			if (need[s] > 0)
			{
				xg.Format("%llu %llu ", s, need[s]);
				objectxrefidx += xg;
			}


		}
		objectxrefidx += "]";

		PDF::astring objectxref;
		objectxref.Format("%llu 0 obj\n<</Type/XRef/%s/W[1 4 2]/Root %llu 0 R/Prev %llu/Info %llu 0 R/Size %llu/ID[<%s><%s>]/Length %llu/Filter/FlateDecode>>stream\n", iObjectXref, objectxrefidx.c_str(),iRoot, (unsigned long long)last.xref.p, iProducer, (unsigned long long )(xrint.size() + lastsize), id1.c_str(), id2.c_str(), (unsigned long long)compressedxref.size());
		uxref.resize(objectxref.size());
		memcpy(uxref.data(), objectxref.data(), objectxref.size());
		long long cu = uxref.size();
		uxref.resize(uxref.size() + cxs);
		memcpy(uxref.data() + cu, compressedxref.data(), compressedxref.size());
		cu = uxref.size();
		objectxref.Format("\nendstream\nendobj\n");
		uxref.resize(cu + objectxref.size());
		memcpy(uxref.data() + cu, objectxref.data(), objectxref.size());
		vafter.insert(vafter.end(), uxref.begin(), uxref.end());
	}
	else
	{
		vafter += xrf;
		trl.Format("trailer\n<</Root %llu 0 R/Prev %llu/Info %llu 0 R/Size %llu/ID[<%s><%s>]>>\n", (unsigned long long)iRoot, (unsigned long long)last.xref.p, (unsigned long long)iProducer, (unsigned long long)( xrint.size() + lastsize), id1.c_str(), id2.c_str());
		vafter += trl;
	}
	sxref.Format("startxref\n%llu\n", (unsigned long long)xrefpos);
	vafter += sxref;
	vafter += vend;

	unsigned long long u2 = vafter.length();
	vafter = "";

	
	if (!InRL)
		vSignatureAfter.Format("/Type/Sig/SubFilter/%s%s/M(D:%s)/ByteRange [0 %llu %llu %03llu]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), extrainsign.c_str(), dd.c_str(), u1, u1 + vs.length(), u2 + 1);
	else
		vSignatureAfter.Format(">/Type/Sig/SubFilter/%s%s/M(D:%s)/ByteRange [0 %llu %llu %03llu]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), extrainsign.c_str(), dd.c_str(), u1, u1 + vs.length(), u2 + 1);


	vafter += vSignatureAfter;
	vafter += vFont;
	vafter += vFont2;

	if (!Params.pdfparams.Visible.t.empty())
	{
		vafter += vVisA1;
		vafter += vVisA2;
		vafter += vVisA3;
		vafter += vVis1;
	}

	vafter += v71;
	vafter.insert(vafter.end(), v72.begin(), v72.end());
	vafter += v73;

//	vafter += v7;			vafter.resize(vafter.size() + 4);			vafter += v7b;
	vafter += vPage;
	vafter += vPages;
	vafter += vRoot;
	vafter += vProducer;

	if (!dss.empty())
	{
		for (long long i = 0; i < dss.size(); i++)
		{
			auto& d = dss[i];
			std::vector<char> vDss;
			vDss.insert(vDss.end(), d.begin(), d.end());
			vafter.insert(vafter.end(), vDss.begin(), vDss.end());
		}
	}

	if (XRefObject)
	{
		vafter.insert(vafter.end(), uxref.begin(), uxref.end());
	}
	else
	{
		vafter += xrf;
		vafter += trl;
	}
	vafter += sxref;
	vafter += vend;

	PDF::AddCh(to_sign, vafter);
	PDF::AddCh(res, vafter);

	ps = to_sign.data();
	ps2 = res.data();

	Params.PAdES = true;
	Params.Attached = AdES::ATTACHTYPE::DETACHED;
	std::vector<char> r;
	auto hrx = Sign(levx, to_sign.data(), (DWORD)to_sign.size(), Certificates, Params, r);
	if (FAILED(hrx))
		return hrx;
	//			AdES::LEVEL lev;
	//			std::vector<char> org;
	//			ad.Verify(r.data(), r.size(), lev, 0, 0, &org);
	//			char* a2 = (char*)org.data();

	char* pv = res.data() + ures;
	if (!InRL)
		pv++;
	for (long long i = 0; i < de; i++)
	{
		if (i >= r.size())
			break;

		unsigned char x = (unsigned char)r[i];
		char g[13];
		sprintf_s(g, 13, "%02X", x);
		memcpy(pv, g, 2);
		pv += 2;
	}
	return S_OK;
}

HRESULT AdES::Sign(LEVEL lev, const char* data, DWORD sz, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& Signature)
{
	using namespace std;
	auto hr = E_FAIL;
	if (!data || !sz)
		return E_INVALIDARG;
	if (Certificates.empty())
		return E_INVALIDARG;

	std::vector<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE> PrivateKeys;
	std::vector<CERT_BLOB> CertsIncluded;
	std::vector<CMSG_SIGNER_ENCODE_INFO> Signers;
	int AuthAttr = CMSG_AUTHENTICATED_ATTRIBUTES_FLAG;
	if (lev == LEVEL::CMS)
		AuthAttr = 0;

	vector <shared_ptr<std::vector<char>>> mem;
	for (auto& c : Certificates)
	{
		if (Params.Debug) printf("Using new certificate...\r\n");
		CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo = { 0 };

		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE a = 0;
		DWORD ks = 0;
		BOOL bfr = false;
		CryptAcquireCertificatePrivateKey(c.cert.cert, 0, 0, &a, &ks, &bfr);
		if (a)
			SignerEncodeInfo.hCryptProv = a;
		if (bfr)
			PrivateKeys.push_back(a);

		SignerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
		SignerEncodeInfo.pCertInfo = c.cert.cert->pCertInfo;
		SignerEncodeInfo.dwKeySpec = ks;
		SignerEncodeInfo.HashAlgorithm = Params.HashAlgorithm;
		SignerEncodeInfo.pvHashAuxInfo = NULL;
		if (AuthAttr)
		{
			// Build also the CaDES-
			CRYPT_ATTRIBUTE* ca = AddMem<CRYPT_ATTRIBUTE>(mem, sizeof(CRYPT_ATTRIBUTE) * (10 + Params.cextras.size()));
			for (auto extra : Params.cextras)
			{
				ca[SignerEncodeInfo.cAuthAttr] = extra;
				SignerEncodeInfo.cAuthAttr++;
			}
			// Add the timestamp
			if (!Params.PAdES)
			{
				if (Params.Debug) printf("Adding local time...\r\n");
				FILETIME ft = { 0 };
				SYSTEMTIME sT = { 0 };
				GetSystemTime(&sT);
				SystemTimeToFileTime(&sT, &ft);
				char buff[1000] = { 0 };
				DWORD buffsize = 1000;
				CryptEncodeObjectEx(PKCS_7_ASN_ENCODING, szOID_RSA_signingTime, (void*)&ft, 0, 0, buff, &buffsize);

				char* bb = AddMem<char>(mem, buffsize);
				memcpy(bb, buff, buffsize);
				CRYPT_ATTR_BLOB* b0 = AddMem<CRYPT_ATTR_BLOB>(mem);
				b0->cbData = buffsize;
				b0->pbData = (BYTE*)bb;
				ca[SignerEncodeInfo.cAuthAttr].pszObjId = szOID_RSA_signingTime;
				ca[SignerEncodeInfo.cAuthAttr].cValue = 1;
				ca[SignerEncodeInfo.cAuthAttr].rgValue = b0;
				SignerEncodeInfo.cAuthAttr++;
			}

			// Hash of the cert
			if (Params.Debug) printf("Adding certificate...\r\n");
			std::vector<BYTE> dhash;
			HASH hash(BCRYPT_SHA256_ALGORITHM);
			hash.hash(c.cert.cert->pbCertEncoded, c.cert.cert->cbCertEncoded);
			hash.get(dhash);
			BYTE* hashbytes = AddMem<BYTE>(mem, dhash.size());
			memcpy(hashbytes, dhash.data(), dhash.size());

			SigningCertificateV2* v = AddMem<SigningCertificateV2>(mem, sizeof(SigningCertificateV2));
			v->certs.list.size = 1;
			v->certs.list.count = 1;
			v->certs.list.array = AddMem<ESSCertIDv2*>(mem);
			v->certs.list.array[0] = AddMem<ESSCertIDv2>(mem);
			v->certs.list.array[0]->certHash.buf = hashbytes;
			v->certs.list.array[0]->certHash.size = (DWORD)dhash.size();
			// SHA-256 is the default

			// Encode it as DER
			std::vector<char> buff3;
			auto ec2 = der_encode(&asn_DEF_SigningCertificateV2,
				v, [](const void *buffer, size_t size, void *app_key) ->int
			{
				std::vector<char>* x = (std::vector<char>*)app_key;
				auto es = x->size();
				x->resize(x->size() + size);
				memcpy(x->data() + es, buffer, size);
				return 0;
			}, (void*)&buff3);
			char* ooodb = AddMem<char>(mem, buff3.size());
			memcpy(ooodb, buff3.data(), buff3.size());
			::CRYPT_ATTR_BLOB bd1 = { 0 };
			bd1.cbData = (DWORD)buff3.size();
			bd1.pbData = (BYTE*)ooodb;
			ca[SignerEncodeInfo.cAuthAttr].pszObjId = "1.2.840.113549.1.9.16.2.47";
			ca[SignerEncodeInfo.cAuthAttr].cValue = 1;
			ca[SignerEncodeInfo.cAuthAttr].rgValue = &bd1;

			SignerEncodeInfo.cAuthAttr++;
			SignerEncodeInfo.rgAuthAttr = ca;

			if (Params.commitmentTypeOid.length())
			{
				if (Params.Debug) printf("Adding commitment type...\r\n");
				std::vector<char> ctt(strlen(Params.commitmentTypeOid.c_str()) + 1);
				memcpy(ctt.data(), Params.commitmentTypeOid.c_str(), strlen(Params.commitmentTypeOid.c_str()));
				OID oid;
				std::vector<unsigned char> cttbin = oid.enc(ctt.data());
				CommitmentTypeIndication* ct = AddMem<CommitmentTypeIndication>(mem, sizeof(CommitmentTypeIndication));
				ct->commitmentTypeId.buf = (uint8_t*)cttbin.data();
				ct->commitmentTypeId.size = (DWORD)cttbin.size();

				std::vector<char> ooo;
				auto ec = der_encode(&asn_DEF_CommitmentTypeIndication,
					ct, [](const void *buffer, size_t size, void *app_key) ->int
				{
					std::vector<char>* x = (std::vector<char>*)app_key;
					auto es = x->size();
					x->resize(x->size() + size);
					memcpy(x->data() + es, buffer, size);
					return 0;
				}, (void*)&ooo);
				char* ooob = AddMem<char>(mem, ooo.size());
				memcpy(ooob, ooo.data(), ooo.size());
				::CRYPT_ATTR_BLOB b1 = { 0 };
				b1.cbData = (DWORD)ooo.size();
				b1.pbData = (BYTE*)ooob;
				ca[SignerEncodeInfo.cAuthAttr].pszObjId = "1.2.840.113549.1.9.16.2.16";
				ca[SignerEncodeInfo.cAuthAttr].cValue = 1;
				ca[SignerEncodeInfo.cAuthAttr].rgValue = &b1;

				SignerEncodeInfo.cAuthAttr++;
			}

			if (Params.Policy.length() > 0)
			{
				if (Params.Debug) printf("Adding policy...\r\n");
				std::vector<char> Polx(Params.Policy.size() + 1);
				memcpy(Polx.data(), Params.Policy.c_str(), Params.Policy.size());
				OID oid;
				std::vector<unsigned char> PolBinary = oid.enc(Polx.data());
				SignaturePolicyIdentifier* v2 = AddMem<SignaturePolicyIdentifier>(mem, sizeof(SignaturePolicyIdentifier));
				v2->present = SignaturePolicyIdentifier_PR_signaturePolicyId;
				v2->choice.signaturePolicyId.sigPolicyId.buf = (uint8_t*)PolBinary.data();
				v2->choice.signaturePolicyId.sigPolicyId.size = (DWORD)PolBinary.size();

				// SHA-1 forced
				v2->choice.signaturePolicyId.sigPolicyHash.hashAlgorithm.algorithm.buf = (uint8_t*)"\x06\x05\x2B\x0E\x03\x02\x1A";
				v2->choice.signaturePolicyId.sigPolicyHash.hashAlgorithm.algorithm.size = 7;

				HASH hb(BCRYPT_SHA1_ALGORITHM);
				hb.hash(v2->choice.signaturePolicyId.sigPolicyId.buf, v2->choice.signaturePolicyId.sigPolicyId.size);
				std::vector<BYTE> hbb;
				hb.get(hbb);
				v2->choice.signaturePolicyId.sigPolicyHash.hashValue.buf = hbb.data();
				v2->choice.signaturePolicyId.sigPolicyHash.hashValue.size = (DWORD)hbb.size();


				std::vector<char> ooo;
				auto ec = der_encode(&asn_DEF_SignaturePolicyIdentifier,
					v2, [](const void *buffer, size_t size, void *app_key) ->int
				{
					std::vector<char>* x = (std::vector<char>*)app_key;
					auto es = x->size();
					x->resize(x->size() + size);
					memcpy(x->data() + es, buffer, size);
					return 0;
				}, (void*)&ooo);
				char* ooob = AddMem<char>(mem, ooo.size());
				memcpy(ooob, ooo.data(), ooo.size());
				::CRYPT_ATTR_BLOB b1 = { 0 };
				b1.cbData = (DWORD)ooo.size();
				b1.pbData = (BYTE*)ooob;
				ca[SignerEncodeInfo.cAuthAttr].pszObjId = "1.2.840.113549.1.9.16.2.15";
				ca[SignerEncodeInfo.cAuthAttr].cValue = 1;
				ca[SignerEncodeInfo.cAuthAttr].rgValue = &b1;

				SignerEncodeInfo.cAuthAttr++;
			}



		}

		Signers.push_back(SignerEncodeInfo);

		CERT_BLOB SignerCertBlob;
		SignerCertBlob.cbData = c.cert.cert->cbCertEncoded;
		SignerCertBlob.pbData = c.cert.cert->pbCertEncoded;
		CertsIncluded.push_back(SignerCertBlob);

		for (auto& cc : c.More)
		{
			CERT_BLOB SignerCertBlob2;
			SignerCertBlob2.cbData = cc.cert->cbCertEncoded;
			SignerCertBlob2.pbData = cc.cert->pbCertEncoded;
			CertsIncluded.push_back(SignerCertBlob2);
		}

	}


	CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo = { 0 };
	SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
	SignedMsgEncodeInfo.cSigners = (DWORD)Signers.size();
	SignedMsgEncodeInfo.rgSigners = Signers.data();
	SignedMsgEncodeInfo.cCertEncoded = (DWORD)CertsIncluded.size();
	SignedMsgEncodeInfo.rgCertEncoded = CertsIncluded.data();
	SignedMsgEncodeInfo.rgCrlEncoded = NULL;


	DWORD dflg = 0;
	if (Params.Attached == ATTACHTYPE::DETACHED)
		dflg = CMSG_DETACHED_FLAG;

	auto cbEncodedBlob = CryptMsgCalculateEncodedLength(
		MY_ENCODING_TYPE,     // Message encoding type
		dflg,
		CMSG_SIGNED,          // Message type
		&SignedMsgEncodeInfo, // Pointer to structure
		NULL,                 // Inner content OID
		(DWORD)sz);
	if (cbEncodedBlob)
	{
		auto hMsg = CryptMsgOpenToEncode(
			MY_ENCODING_TYPE,        // encoding type
			dflg | AuthAttr,
			CMSG_SIGNED,             // message type
			&SignedMsgEncodeInfo,    // pointer to structure
			NULL,                    // inner content OID
			NULL);
		if (hMsg)
		{
			// Add the signature
			if (Params.Debug) printf("Signing...\r\n");
			Signature.resize(cbEncodedBlob);
			if (CryptMsgUpdate(hMsg, (BYTE*)data, (DWORD)sz, true))
			{
				if (CryptMsgGetParam(
					hMsg,               // Handle to the message
					CMSG_CONTENT_PARAM, // Parameter type
					0,                  // Index
					(BYTE*)Signature.data(),      // Pointer to the BLOB
					&cbEncodedBlob))    // Size of the BLOB
				{
					Signature.resize(cbEncodedBlob);
					hr = S_OK;
					if (hMsg)
					{
						CryptMsgClose(hMsg);
						hMsg = 0;
					}

					if (hr == S_OK && lev >= LEVEL::T)
					{
						hr = E_FAIL;
						if (Params.Debug) printf("Adding trusted timestamp...\r\n");
						hr = AddCT(Signature, Certificates, Params);

						if (hr == S_OK && lev >= LEVEL::C)
						{
							if (Params.Debug) printf("Adding C level...\r\n");
							auto[hr2, full1, full2] = AddCC(Signature, Certificates, Params);
							hr = hr2;
							if (hr == S_OK && lev >= LEVEL::X)
							{
								hr = E_FAIL;
								if (Params.Debug) printf("Adding X level...\r\n");
								hr = AddCX(Signature, Certificates, Params, full1, full2);

								if (hr == S_OK && lev >= LEVEL::XL)
								{
									// Add complete certs
									hr = E_FAIL;
									if (Params.Debug) printf("Adding XL level...\r\n");
									hr = AddCXL(Signature, Certificates, Params);
								}
							}
						}
					}
				}
			}
			if (hMsg)
				CryptMsgClose(hMsg);
			hMsg = 0;
		}
	}

	for (auto& a : PrivateKeys)
	{
		if (NCryptIsKeyHandle(a))
			NCryptFreeObject(a);
		else
			CryptReleaseContext(a, 0);
	}
	if (Params.Debug) printf("Completed.\r\n");
	return hr;
}



inline std::wstring TempFile(wchar_t* x, const wchar_t* prf)
{
	std::vector<wchar_t> td(1000);
	GetTempPathW(1000, td.data());
	GetTempFileNameW(td.data(), prf, 0, x);
	return x;
}


#define USE_XZIP
#ifdef USE_XZIP
#include "xzip.hpp"
namespace ZIPUTILS
{
	class ZIP
	{
		HZIP zz = 0;
	public:


		~ZIP()
		{
			if (zz)
				CloseZip(zz);
			zz = 0;
		}

		ZIP(const char* fn)
		{
			std::wstring fi = XML3::XMLU(fn);
			zz = CreateZip((void*)fi.c_str(), 0, ZIP_FILENAME);
		}

		bool PutFile(const char* ref, const char* d, size_t sz)
		{
			std::wstring fi = XML3::XMLU(ref);
			ZipAdd(zz, fi.c_str(),(void*) d, sz, ZIP_FILENAME);
			return false;
		}
	};
}
#else
#include "zipall.hpp"
#endif

HRESULT AdES::ASiC(ALEVEL alev, ATYPE typ,LEVEL lev, std::vector<FILEREF>& data, std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& fndata)
{
	using namespace std;
	HRESULT hr = E_FAIL;
	fndata.clear();

	if (alev == ALEVEL::S)
	{
		if (data.size() != 1)
			return E_INVALIDARG;
		auto& t = data[0];

		wchar_t x[1000] = { 0 };
		wstring wtempf = TempFile(x, L"asic");
		string tempf = XML3::XMLU(wtempf.c_str());
		DeleteFileA(tempf.c_str());
		ZIPUTILS::ZIP z(tempf.c_str());

		string mt = "application/vnd.etsi.asic-s+zip";
		z.PutFile("mimetype", mt.c_str(), (DWORD)mt.length());
		z.PutFile(t.ref, (const char*)t.data, t.sz);
		//		z.PutDirectory("META-INF");

		if (typ == ATYPE::CADES)
		{
			std::vector<char> S;
			Params.Attached = AdES::ATTACHTYPE::DETACHED;
			hr = Sign(lev, (const char*)t.data, t.sz, Certificates, Params, S);
			if (FAILED(hr))
			{
				DeleteFile(wtempf.c_str());
				return hr;
			}
			z.PutFile("META-INF/signature.p7s", S.data(), (DWORD)S.size());
			LoadFile(wtempf.c_str(), fndata);
			DeleteFile(wtempf.c_str());
		}
		else
		{
			std::vector<char> S;
			Params.Attached = AdES::ATTACHTYPE::DETACHED;
			Params.ASiC = true;

			hr = XMLSign(lev, data, Certificates, Params, S);
			if (FAILED(hr))
			{
				DeleteFile(wtempf.c_str());
				return hr;
			}
			S.resize(S.size() + 1);
			XML3::XML x2;
			x2.Parse(S.data(), S.size());

			XML3::XMLElement el;
			el.SetElementName("asic:XAdESSignatures");
			el.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
			el.vv("xmlns:asic") = "http://uri.etsi.org/02918/v1.2.1#";
			el.vv("xmlns:xsi") = "http://www.w3.org/2001/XMLSchema-instance";
			el.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";

			el.AddElement(x2.GetRootElement());
			x2.SetRootElement(el);

			XML3::XMLSerialization ser;
			ser.Canonical = true;
			auto ns = x2.Serialize(&ser);
			z.PutFile("META-INF/signatures.xml", ns.data(), (DWORD)ns.size());
			LoadFile(wtempf.c_str(), fndata);
			DeleteFile(wtempf.c_str());
		}

	}
	else
	{
		// Extended
		if (data.size() == 0)
			return E_INVALIDARG;

		wchar_t x[1000] = { 0 };
		wstring wtempf = TempFile(x, L"asic");
		string tempf = XML3::XMLU(wtempf.c_str());
		DeleteFileA(tempf.c_str());
		ZIPUTILS::ZIP z(tempf.c_str());

		string mt = "application/vnd.etsi.asic-e+zip";
		z.PutFile("mimetype", mt.c_str(), (DWORD)mt.length());

		for (auto& t : data)
		{
			z.PutFile(t.ref, (const char*)t.data, t.sz);
		}


		XML3::XML ASiCManifest;
		ASiCManifest.GetRootElement().SetElementName("ASiCManifest");
		ASiCManifest.GetRootElement().vv("xmlns") = "http://uri.etsi.org/02918/v1.2.1#";
		ASiCManifest.GetRootElement().vv("xmlns:ns2") = "http://www.w3.org/2000/09/xmldsig#";
		ASiCManifest.GetRootElement()["SigReference"].vv("URI") = "META-INF/signature.p7s";
		ASiCManifest.GetRootElement()["SigReference"].vv("MimeType") = "application/x-pkcs7-signature";

		for (auto& t : data)
		{

			auto& ref = ASiCManifest.GetRootElement().AddElement("DataObjectReference");
			ref.vv("URI") = t.ref;
			// 		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			auto& d = ref.AddElement("ns2:DigestMethod");
			d.vv("Algorithm") = "http://www.w3.org/2001/04/xmlenc#sha256";

			auto& d2 = ref.AddElement("ns2:DigestValue");

			HASH h(BCRYPT_SHA256_ALGORITHM);
			h.hash((BYTE*)t.data, t.sz);
			std::vector<BYTE> ddd;
			h.get(ddd);

			string a = XML3::Char2Base64((char*)ddd.data(), ddd.size(), false);
			d2.SetContent(a.c_str());
		}

		XML3::XMLSerialization ser;
		ser.Canonical = true;
		string s = ASiCManifest.Serialize(&ser);
		z.PutFile("META-INF/ASiCManifest.xml", (const char*)s.data(), (DWORD)s.size());

		std::vector<char> S;
		Params.Attached = AdES::ATTACHTYPE::DETACHED;
		Params.ASiC = true;
	
		if (typ == ATYPE::CADES)
		{
			hr = Sign(LEVEL::XL, (const char*)s.data(), (DWORD)s.size(), Certificates, Params, S);
			if (FAILED(hr))
			{
				DeleteFile(wtempf.c_str());
				return hr;
			}
			z.PutFile("META-INF/signature.p7s", (const char*)S.data(), (DWORD)S.size());
			LoadFile(wtempf.c_str(), fndata);
			DeleteFile(wtempf.c_str());
		}
		else
		{
		//  s = ASiCManifest.GetRootElement().Serialize(&ser);
/*			auto tu = make_tuple<const BYTE*, DWORD, const char*>(std::forward<const BYTE*>((BYTE*)s.data()), 0, 0);
			std::get<1>(tu) =(DWORD) s.size();
			std::get<2>(tu) = "META-INF/ASiCManifest.xml";
			std::vector<tuple<const BYTE*, DWORD, const char*>> tu2 = { tu };
			hr = XMLSign(lev, tu2, Certificates, Params, S);
*/
			FILEREF tu(s.data(), 0, 0);
			std::vector<FILEREF> tu2 = { tu };
			hr = XMLSign(lev, tu2, Certificates, Params, S);
			if (FAILED(hr))
			{
				DeleteFile(wtempf.c_str());
				return hr;
			}
			S.resize(S.size() + 1);
			XML3::XML x2;
			x2.Parse(S.data(), S.size());

			XML3::XMLElement el;
			el.SetElementName("asic:XAdESSignatures");
			el.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
			el.vv("xmlns:asic") = "http://uri.etsi.org/02918/v1.2.1#";
			el.vv("xmlns:xsi") = "http://www.w3.org/2001/XMLSchema-instance";
			el.vv("xmlns:xades") = "http://uri.etsi.org/01903/v1.3.2#";

			el.AddElement(x2.GetRootElement());
			x2.SetRootElement(el);

	
			auto ns = x2.Serialize(&ser);
			z.PutFile("META-INF/signatures.xml", ns.data(), (DWORD)ns.size());
			LoadFile(wtempf.c_str(), fndata);
			DeleteFile(wtempf.c_str());

		}
	}

	return hr;
}

