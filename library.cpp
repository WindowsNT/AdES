#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#define CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS
#include <string>
#include <tuple>
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

using namespace std;

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
inline bool LoadFile(const wchar_t* f, vector<T>& d)
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


	vector<unsigned char>abBinary;


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

	bool get(vector<BYTE>& b)
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

inline vector<char> StripASNTagLength(vector<char>& d)
{
	vector<char> x = d;

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


inline void LenPush(unsigned char s, vector<char>& x, DWORD sz)
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

inline vector<char> EncodeCertList(vector<PCCERT_CONTEXT>& d)
{
	// 	CertificateValues :: = SEQUENCE OF Certificate
	vector<char> x;
	DWORD sz = 0;
	for (auto& dd : d)
	{
		sz += dd->cbCertEncoded;
	}
	LenPush(0x30, x, sz);
	for (auto& dd : d)
	{
		vector<char> dz(dd->cbCertEncoded);
		memcpy(dz.data(), dd->pbCertEncoded, dd->cbCertEncoded);
		x.insert(x.end(), dz.begin(), dz.end());
	}

	return x;
}

inline vector<char> EncodeCRLList(vector<PCCRL_CONTEXT>& d)
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
		vector<char> buff3;
		auto ec2 = der_encode(&asn_DEF_TestTest,
			&tt, [](const void *buffer, size_t size, void *app_key) ->int
		{
			vector<char>* x = (vector<char>*)app_key;
			auto es = x->size();
			x->resize(x->size() + size);
			memcpy(x->data() + es, buffer, size);
			return 0;
		}, (void*)&buff3);
	*/

	vector<char> x;

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
		vector<char> dz(dd->cbCrlEncoded);
		memcpy(dz.data(), dd->pbCrlEncoded, dd->cbCrlEncoded);
		x.insert(x.end(), dz.begin(), dz.end());
	}


	// x has the seq of CRLs

	// We must also put the explicit tag 0xa0 <length>
	vector<char> x3;
	LenPush(0xa0, x3,(DWORD) x.size());
	x3.insert(x3.end(), x.begin(), x.end());

	vector<char> x2;
	LenPush(0x30, x2, (DWORD)x3.size());
	x2.insert(x2.end(), x3.begin(), x3.end());
	return x2;
}

AdES::AdES()
{

}

HRESULT AdES::VerifyB(const char* data, DWORD sz, int sidx, bool Attached, PCCERT_CONTEXT c)
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
				vector<char> ca;
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
							vector<char> bu(10000);
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
								vector<BYTE> dhash;
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
			vector<char> ca;
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

HRESULT AdES::VerifyT(const char* data, DWORD sz, PCCERT_CONTEXT* pX, bool Attached, int TSServerSignIndex, FILETIME* ft)
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
			vector<char> ca;
			DWORD da = 0;

			if (CryptMsgGetParam(
				hMsg,                  // Handle to the message
				CMSG_ENCRYPTED_DIGEST,  // Parameter type
				TSServerSignIndex,                     // Index
				NULL,                  // Address for returned information
				&da))       // Size of the returned information
			{
				vector<char> EH(da);
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

HRESULT AdES::TimeStamp(CRYPT_TIMESTAMP_PARA params, const char* data, DWORD sz, vector<char>& Result, const wchar_t* url, const char* alg)
{
	CRYPT_TIMESTAMP_CONTEXT*re;
	auto flg = TIMESTAMP_VERIFY_CONTEXT_SIGNATURE;

	if (!CryptRetrieveTimeStamp(url, flg, 0, alg, &params, (BYTE*)data, (DWORD)sz, &re, 0, 0))
		return E_FAIL;
	vector<char>& CR = Result;
	CR.resize(re->cbEncoded);
	memcpy(CR.data(), re->pbEncoded, re->cbEncoded);
	CryptMemFree(re);
	return S_OK;
}

HRESULT AdES::Verify(const char* data, DWORD sz, LEVEL& lev, const char* omsg, DWORD len, std::vector<char>* msg, std::vector<PCCERT_CONTEXT>* Certs, VERIFYRESULTS* vr)
{
	auto hr = E_FAIL;

	CRYPT_VERIFY_MESSAGE_PARA VerifyParams = { 0 };
	VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
	VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
	VerifyParams.hCryptProv = 0;
	VerifyParams.pfnGetSignerCertificate = NULL;
	VerifyParams.pvGetArg = NULL;
	vector<char> zud;
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
			auto hr1 = VerifyB(data, sz, i, omsg ? false : true, c);
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
						vector<char> ca;
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
										vector<char> sp(v->choice.signaturePolicyId.sigPolicyId.size + 1);
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
										vector<char> sp(v->commitmentTypeId.size + 1);
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


HRESULT AdES::GetEncryptedHash(const char*d, DWORD sz, PCCERT_CONTEXT ctx, CRYPT_ALGORITHM_IDENTIFIER hash, vector<char>& rs)
{

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
	vector<char> Sig(blb);
	CryptSignMessage(&spar, true, 1, MessageArray, rbs, (BYTE*)Sig.data(), &blb);
	Sig.resize(blb);
	string dss = XML3::Char2Base64((const char*)Sig.data(), Sig.size(), false);
	sv.SetContent(dss.c_str());
*/
	HRESULT hr = E_FAIL;
	vector<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE> PrivateKeys;
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
			vector<char> Sig2(cbEncodedBlob);
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

HRESULT AdES::XMLSign(LEVEL lev, std::vector<std::tuple<const BYTE*, DWORD, const char*>>& dat,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& Signature)
{

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

	auto algfrom = [&]() -> string
	{
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha256) == 0)
			return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
		return "";
	};
	auto alg2from = [&]() -> string
	{
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			return "http://www.w3.org/2000/09/xmldsig#sha1";
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha256) == 0)
			return "http://www.w3.org/2001/04/xmlenc#sha256";
		return "";
	};
	auto alg3from = [&]() -> LPWSTR
	{
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			return BCRYPT_SHA1_ALGORITHM;
		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_NIST_sha256) == 0)
			return BCRYPT_SHA256_ALGORITHM;
		return L"";
	};

	auto remprefix = [](XML3::XMLElement& r)
	{
		vector<shared_ptr<XML3::XMLElement>> allc;
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



	auto hr = E_FAIL;
	Signature.clear();
	if (Params.Attached == ATTACHTYPE::ENVELOPED)
	{
		if (dat.size() != 1)
			return E_INVALIDARG;
		if (std::get<1>(dat[0]) != 0)
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
	vector<BYTE> dhash;
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
		ds_SignedInfo["ds:CanonicalizationMethod"].vv("Algorithm") = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
		ds_SignedInfo["ds:SignatureMethod"].vv("Algorithm") = algfrom();

		for (auto& data : dat)
		{
			auto URIRef = std::get<2>(data);
			string ss;
			if (std::get<1>(data) == 0)
			{
				x.Clear();
				auto xp = x.Parse((char*)std::get<0>(data), strlen((char*)std::get<0>(data)));
				if (xp != XML3::XML_PARSE::OK)
					return E_UNEXPECTED;

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
				ss.assign((char*)std::get<0>(data), std::get<1>(data));
			}

			auto& ref1 = ds_SignedInfo.AddElement("ds:Reference");
			ref1.vv("URI") = "";
			if (URIRef && Params.Attached == ATTACHTYPE::DETACHED)
				ref1.vv("URI") = URIRef;
			if (URIRef && Params.Attached == ATTACHTYPE::ENVELOPING)
			{
				// With #
				sprintf_s(d, 1000, "#%s", URIRef);
				ref1.vv("URI") = d;
			}

			if (std::get<1>(data) == 0)
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
			auto& xce = xsc.AddElement("xades:Cert");
			auto& xced = xce.AddElement("xades:CertDigest");
			auto& xces = xce.AddElement("xades:IssuerSerialV2");

			xced["ds:DigestMethod"].vv("Algorithm") = alg2from();

			auto srl = certsrl(Certificates[iCert].cert.cert);
			sprintf_s(d, 1000, "%llu", srl);
			xces["ds:X509SerialNumber"].SetContent(d);

			vector<BYTE> dhash3;
			LPWSTR alg3 = alg3from();
			HASH hash33(alg3);
			hash33.hash(Certificates[iCert].cert.cert->pbCertEncoded, Certificates[iCert].cert.cert->cbCertEncoded);
			hash33.get(dhash3);
			string dx = XML3::Char2Base64((char*)dhash3.data(), dhash3.size(), false);
			xced["ds:DigestValue"].SetContent(dx.c_str());

			auto& xsdop = xsp.AddElement("xades:SignedDataObjectProperties");


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
				vector<BYTE> hbb;
				hb.get(hbb);
				string dd2 = XML3::Char2Base64((char*)hbb.data(), hbb.size(), false);
				xspolid3["ds:DigestValue"].SetContent(dd2.c_str());
			}


			// Commitment
			if (Params.commitmentTypeOid.length())
			{
				auto& xcti = xsdop.AddElement("xades:CommitmentTypeIndication");
				auto& xctid = xcti.AddElement("xades:CommitmentTypeId");
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
			ref2.vv("URI") = d;
			ref2.vv("Type") = "http://uri.etsi.org/01903#SignedProperties";


			ref2["ds:Transforms"]["ds:Transform"].vv("Algorithm") = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

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
			//ref2.vv("Type") = "http://uri.etsi.org/01903#SignedProperties";

			ref3["ds:Transforms"]["ds:Transform"].vv("Algorithm") = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

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
				/*<xades:UnsignedSignatureProperties>
								<xades:SignatureTimeStamp>
									<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
									<xades:EncapsulatedTimeStamp>*/
				auto& xusp = xup.AddElement("xades:UnsignedSignatureProperties");
				auto& xstt = xusp.AddElement("xades:SignatureTimeStamp");
				xstt["ds:CanonicalizationMethod"].vv("Algorithm") = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

				XML3::XMLElement c = "xades:EncapsulatedTimeStamp";
				tscontent = xstt.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(c));

				if (lev >= LEVEL::C)
				{
					XML3::XMLElement c1 = "xades:CompleteCertificateRefs";
					cc1 = xusp.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(c1));

					XML3::XMLElement c2 = "xades:CompleteRevocationRefs";
					cc2 = xusp.InsertElement((size_t)-1, std::forward<XML3::XMLElement>(c2));
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


		vector<char> Sig;
		hr = GetEncryptedHash(sf.data(), (DWORD)sf.size(), Certificates[iCert].cert.cert, Params.HashAlgorithm, Sig);
		string dss = XML3::Char2Base64((const char*)Sig.data(), Sig.size(), false);
		sv.SetContent(dss.c_str());

		if (lev >= LEVEL::T)
		{
			string svs = sv.Serialize(&ser);
			vector<char> tsr;
			TimeStamp(Params.tparams, (char*)svs.data(), (DWORD)svs.size(), tsr, Params.TSServer);
			string b = XML3::Char2Base64(tsr.data(), tsr.size(), false);
			tscontent->SetContent(b.c_str());
		}



		ds_Signature.AddElement(sv);
		ds_Signature.AddElement(ki);
		if (lev != LEVEL::XMLDSIG)
		{
			ds_Signature.AddElement(o2);
		}

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
					auto URIRef = std::get<2>(data);
					XML3::XMLElement enveloping = lev == LEVEL::XMLDSIG ? "Object" : "ds:Object";
					enveloping.vv("xmlns:ds") = "http://www.w3.org/2000/09/xmldsig#";
					enveloping.vv("Id") = URIRef;

					XML3::XML x4;
					x4.Parse((char*)std::get<0>(data), strlen((char*)std::get<0>(data)));

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

void hd(vector<char> d)
{
	string e;
	char ee[10];
	for (auto c : d)
	{
		sprintf_s(ee, 10, "%02X", c);
		e += ee;
	}
	MessageBoxA(0, e.c_str(), 0, 0);
}

HRESULT AdES::AddCT(vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params)
{
	HRESULT hr = E_FAIL;
	DWORD dflg = 0;
	if (Params.Attached == ATTACHTYPE::DETACHED)
		dflg = CMSG_DETACHED_FLAG;
	DWORD cbEncodedBlob = 0;

	vector<char> EH;
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

						vector<char> CR;
						auto hrx = TimeStamp(Params.tparams, EH.data(), (DWORD)EH.size(), CR, Params.TSServer);
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
							vector<char> enc(aa);
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



std::tuple<HRESULT, vector<char>, vector<char>>  AdES::AddCC(vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params)
{
	HRESULT hr = E_FAIL;
	DWORD dflg = 0;
	if (Params.Attached == ATTACHTYPE::DETACHED)
		dflg = CMSG_DETACHED_FLAG;
	vector <shared_ptr<vector<char>>> mem;
	DWORD cbEncodedBlob = 0;


	vector<char> buff3;
	vector<char> buff5;
	vector<char> full1;
	vector<char> full2;

	vector<char> EH;
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
					vector<BYTE> dhash;
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
					vector<char>* x = (vector<char>*)app_key;
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
					vector<char> enc(aa);
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
						vector<BYTE> dhash;
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
					vector<char>* x = (vector<char>*)app_key;
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
					vector<char> enc(aa);
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

	vector<char> EH;
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
				vector<char> EH2 = StripASNTagLength(full1);
				vector<char> EH3 = StripASNTagLength(full2);
				EH2.insert(EH2.end(), EH3.begin(), EH3.end());

				vector<BYTE> dhash;
				HASH hash(BCRYPT_SHA256_ALGORITHM);
				hash.hash((BYTE*)EH2.data(), (DWORD)EH2.size());
				hash.get(dhash);

				vector<char> CR;
				auto hrx = TimeStamp(Params.tparams, EH2.data(), (DWORD)EH2.size(), CR, Params.TSServer);
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
					vector<char> enc(aa);
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

	vector<char> EH;
	auto hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, dflg, 0, 0, 0, 0);
	if (hMsg)
	{
		if (CryptMsgUpdate(hMsg, (BYTE*)Signature.data(), (DWORD)Signature.size(), TRUE))           // Last call
		{
			// Get the encrypted hash for timestamp
			bool S = true;
			for (DWORD i = 0; i < Certificates.size(); i++)
			{
				vector<PCCERT_CONTEXT> ve;
				vector<PCCRL_CONTEXT> vcrls;
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
					vector<char> enc(aa);
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
					vector<char> enc(aa);
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


HRESULT AdES::Sign(LEVEL lev, const char* data, DWORD sz, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& Signature)
{
	auto hr = E_FAIL;
	if (!data || !sz)
		return E_INVALIDARG;
	if (Certificates.empty())
		return E_INVALIDARG;

	vector<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE> PrivateKeys;
	vector<CERT_BLOB> CertsIncluded;
	vector<CMSG_SIGNER_ENCODE_INFO> Signers;
	int AuthAttr = CMSG_AUTHENTICATED_ATTRIBUTES_FLAG;
	if (lev == LEVEL::CMS)
		AuthAttr = 0;

	vector <shared_ptr<vector<char>>> mem;
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
			CRYPT_ATTRIBUTE* ca = AddMem<CRYPT_ATTRIBUTE>(mem, sizeof(CRYPT_ATTRIBUTE) * 10);
			// Add the timestamp
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
			ca[0].pszObjId = szOID_RSA_signingTime;
			ca[0].cValue = 1;
			ca[0].rgValue = b0;

			// Hash of the cert
			if (Params.Debug) printf("Adding certificate...\r\n");
			vector<BYTE> dhash;
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
			vector<char> buff3;
			auto ec2 = der_encode(&asn_DEF_SigningCertificateV2,
				v, [](const void *buffer, size_t size, void *app_key) ->int
			{
				vector<char>* x = (vector<char>*)app_key;
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
			ca[1].pszObjId = "1.2.840.113549.1.9.16.2.47";
			ca[1].cValue = 1;
			ca[1].rgValue = &bd1;

			SignerEncodeInfo.cAuthAttr = 2;
			SignerEncodeInfo.rgAuthAttr = ca;

			if (Params.commitmentTypeOid.length())
			{
				if (Params.Debug) printf("Adding commitment type...\r\n");
				vector<char> ctt(strlen(Params.commitmentTypeOid.c_str()) + 1);
				memcpy(ctt.data(), Params.commitmentTypeOid.c_str(), strlen(Params.commitmentTypeOid.c_str()));
				OID oid;
				vector<unsigned char> cttbin = oid.enc(ctt.data());
				CommitmentTypeIndication* ct = AddMem<CommitmentTypeIndication>(mem, sizeof(CommitmentTypeIndication));
				ct->commitmentTypeId.buf = (uint8_t*)cttbin.data();
				ct->commitmentTypeId.size = (DWORD)cttbin.size();

				vector<char> ooo;
				auto ec = der_encode(&asn_DEF_CommitmentTypeIndication,
					ct, [](const void *buffer, size_t size, void *app_key) ->int
				{
					vector<char>* x = (vector<char>*)app_key;
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
				vector<char> Polx(Params.Policy.size() + 1);
				memcpy(Polx.data(), Params.Policy.c_str(), Params.Policy.size());
				OID oid;
				vector<unsigned char> PolBinary = oid.enc(Polx.data());
				SignaturePolicyIdentifier* v2 = AddMem<SignaturePolicyIdentifier>(mem, sizeof(SignaturePolicyIdentifier));
				v2->present = SignaturePolicyIdentifier_PR_signaturePolicyId;
				v2->choice.signaturePolicyId.sigPolicyId.buf = (uint8_t*)PolBinary.data();
				v2->choice.signaturePolicyId.sigPolicyId.size = (DWORD)PolBinary.size();

				// SHA-1 forced
				v2->choice.signaturePolicyId.sigPolicyHash.hashAlgorithm.algorithm.buf = (uint8_t*)"\x06\x05\x2B\x0E\x03\x02\x1A";
				v2->choice.signaturePolicyId.sigPolicyHash.hashAlgorithm.algorithm.size = 7;

				HASH hb(BCRYPT_SHA1_ALGORITHM);
				hb.hash(v2->choice.signaturePolicyId.sigPolicyId.buf, v2->choice.signaturePolicyId.sigPolicyId.size);
				vector<BYTE> hbb;
				hb.get(hbb);
				v2->choice.signaturePolicyId.sigPolicyHash.hashValue.buf = hbb.data();
				v2->choice.signaturePolicyId.sigPolicyHash.hashValue.size = (DWORD)hbb.size();


				vector<char> ooo;
				auto ec = der_encode(&asn_DEF_SignaturePolicyIdentifier,
					v2, [](const void *buffer, size_t size, void *app_key) ->int
				{
					vector<char>* x = (vector<char>*)app_key;
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


#include "zipall.hpp"

inline wstring TempFile(wchar_t* x, const wchar_t* prf)
{
	vector<wchar_t> td(1000);
	GetTempPathW(1000, td.data());
	GetTempFileNameW(td.data(), prf, 0, x);
	return x;
}



HRESULT AdES::ASiC(ALEVEL alev, ATYPE typ,LEVEL lev, std::vector<std::tuple<const BYTE*, DWORD, const char*>>& data, std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& fndata)
{
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
		z.PutFile(std::get<2>(t), (const char*)std::get<0>(t), std::get<1>(t));
		//		z.PutDirectory("META-INF");

		if (typ == ATYPE::CADES)
		{
			vector<char> S;
			Params.Attached = AdES::ATTACHTYPE::DETACHED;
			hr = Sign(lev, (const char*)std::get<0>(t), std::get<1>(t), Certificates, Params, S);
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
			vector<char> S;
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
			z.PutFile(std::get<2>(t), (const char*)std::get<0>(t), std::get<1>(t));
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
			ref.vv("URI") = std::get<2>(t);
			// 		if (strcmp(Params.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) == 0)
			auto& d = ref.AddElement("ns2:DigestMethod");
			d.vv("Algorithm") = "http://www.w3.org/2001/04/xmlenc#sha256";

			auto& d2 = ref.AddElement("ns2:DigestValue");

			HASH h(BCRYPT_SHA256_ALGORITHM);
			h.hash(std::get<0>(t), std::get<1>(t));
			vector<BYTE> ddd;
			h.get(ddd);

			string a = XML3::Char2Base64((char*)ddd.data(), ddd.size(), false);
			d2.SetContent(a.c_str());
		}

		XML3::XMLSerialization ser;
		ser.Canonical = true;
		string s = ASiCManifest.Serialize(&ser);
		z.PutFile("META-INF/ASiCManifest.xml", (const char*)s.data(), (DWORD)s.size());

		vector<char> S;
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
			auto tu = make_tuple<const BYTE*, DWORD, const char*>(std::forward<const BYTE*>((BYTE*)s.data()), 0, 0);
			std::get<1>(tu) =(DWORD) s.size();
			std::get<2>(tu) = "META-INF/ASiCManifest.xml";
			vector<tuple<const BYTE*, DWORD, const char*>> tu2 = { tu };
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