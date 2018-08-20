#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#include <string>
#include <windows.h>
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
#include "SigningCertificateV2.h"
#include "SignaturePolicyId.h"
using namespace std;


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
				unsigned char cl = ((*pb & 0xC0) >> 6) & 0x03;
				switch (cl)
				{
				}
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
				sprintf_s(fOut,100,".%d.%d", *pb / 40, *pb % 40);
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

				sprintf_s(fOut,100, ".%lu", ll);
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

	std::vector<unsigned char> enc( char* oid)
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

AdES::AdES()
{

}

HRESULT AdES::VerifyB(const char* data, DWORD sz, int sidx,bool Attached,PCCERT_CONTEXT c)
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
						if (strcmp(attr.pszObjId,"1.2.840.113549.1.9.3") == 0) // Content Type
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
								attr.rgValue[0].pbData, attr.rgValue[0].cbData,0);
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

HRESULT AdES :: VerifyT(const char* data, DWORD sz, PCCERT_CONTEXT* pX, bool Attached, int TSServerSignIndex, FILETIME* ft)
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
									if (strcmp(si->rgAttr[a].pszObjId, TsOid) == 0 && si->rgAttr[a].cValue == 1)
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

HRESULT AdES :: TimeStamp(CRYPT_TIMESTAMP_PARA params,const char* data, DWORD sz, vector<char>& Result, const wchar_t* url,const char* alg)
{
	CRYPT_TIMESTAMP_CONTEXT*re;
	auto flg = TIMESTAMP_VERIFY_CONTEXT_SIGNATURE;

	if (!CryptRetrieveTimeStamp(url, flg, 0,alg, &params, (BYTE*)data, (DWORD)sz, &re, 0, 0))
		return E_FAIL;
	vector<char>& CR = Result;
	CR.resize(re->cbEncoded);
	memcpy(CR.data(), re->pbEncoded, re->cbEncoded);
	CryptMemFree(re);
	return S_OK;
}

HRESULT AdES::Verify(const char* data, DWORD sz, CLEVEL& lev,const char* omsg, DWORD len,std::vector<char>* msg,std::vector<PCCERT_CONTEXT>* Certs, std::vector<std::string>* Policies)
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
			ZRS = omsg ? CryptVerifyDetachedMessageSignature(&VerifyParams, i, (BYTE*)data, (DWORD)sz, 1, rgpbToBeSigned, bb, Certs ? &c : 0) : CryptVerifyMessageSignature(&VerifyParams, i, (BYTE*)data, (DWORD)sz, (BYTE*)zud.data(), &pzud, Certs ? &c : 0);
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
			lev = CLEVEL::CMS;

			// Check now BES
			auto hr1 = VerifyB(data, sz, i, omsg ? false : true,c);
			if (SUCCEEDED(hr1))
			{
				lev = CLEVEL::CADES_B;
				// Check now T
				FILETIME ft = { 0 };
				auto hr2 = VerifyT(data, sz, 0, omsg ? false : true, i, &ft);
				if (SUCCEEDED(hr2))
					lev = CLEVEL::CADES_T;
			}
		}
	}

	if (SUCCEEDED(hr) && Policies)
	{
		// Return also the policy
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
									SignaturePolicyId* v = 0;
									auto rval = asn_DEF_SignaturePolicyId.ber_decoder(0,
										&asn_DEF_SignaturePolicyId,
										(void **)&v,
										attr.rgValue[0].pbData, attr.rgValue[0].cbData, 0);
									if (v)
									{
										vector<char> sp(v->sigPolicyId.size + 1);
										memcpy_s(sp.data(),v->sigPolicyId.size + 1, v->sigPolicyId.buf, v->sigPolicyId.size);
										OID oid;
										string sdec = oid.dec(sp.data(), v->sigPolicyId.size);
										Policies->push_back(sdec);
										asn_DEF_SignaturePolicyId.free_struct(&asn_DEF_SignaturePolicyId, v, 0);
										v = 0;
									}
								}
							}
						}
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

HRESULT AdES::Sign(CLEVEL Level, const char* data, DWORD sz, const vector<PCCERT_CONTEXT>& Certificates, const vector<PCCERT_CONTEXT>& AddCertificates, SIGNPARAMETERS& Params,vector<char>& Signature)
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
	if (Level == CLEVEL::CMS)
		AuthAttr = 0;

	vector <shared_ptr<vector<char>>> mem;
	for (auto& c : Certificates)
	{
		CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo = { 0 };

		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE a = 0;
		DWORD ks = 0;
		BOOL bfr = false;
		CryptAcquireCertificatePrivateKey(c, 0, 0, &a, &ks, &bfr);
		if (a)
			SignerEncodeInfo.hCryptProv = a;
		if (bfr)
			PrivateKeys.push_back(a);

		SignerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
		SignerEncodeInfo.pCertInfo = c->pCertInfo;
		SignerEncodeInfo.dwKeySpec = ks;
		SignerEncodeInfo.HashAlgorithm = Params.HashAlgorithm;
		SignerEncodeInfo.pvHashAuxInfo = NULL;
		if (AuthAttr)
		{
			// Build also the CaDES-
			CRYPT_ATTRIBUTE* ca = AddMem<CRYPT_ATTRIBUTE>(mem, sizeof(CRYPT_ATTRIBUTE) * 3);
			// Add the timestamp
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
			vector<BYTE> dhash;
			HASH hash(BCRYPT_SHA256_ALGORITHM);
			hash.hash(c->pbCertEncoded, c->cbCertEncoded);
			hash.get(dhash);
			BYTE* hashbytes = AddMem<BYTE>(mem, dhash.size());
			memcpy(hashbytes, dhash.data(), dhash.size());

			SigningCertificateV2* v = AddMem<SigningCertificateV2>(mem,sizeof(SigningCertificateV2));
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

			if (Params.Policy.length() > 0)
			{
				vector<char> Polx(Params.Policy.size() + 1);
				memcpy(Polx.data(), Params.Policy.c_str(), Params.Policy.size());
				OID oid;
				vector<unsigned char> PolBinary = oid.enc(Polx.data());
				SignaturePolicyId* v2 = AddMem<SignaturePolicyId>(mem, sizeof(SignaturePolicyId));
				v2->sigPolicyId.buf = (uint8_t*)PolBinary.data();
				v2->sigPolicyId.size = (DWORD)PolBinary.size();
				
				// SHA-1 forced
				v2->sigPolicyHash.hashAlgorithm.algorithm.buf = (uint8_t*)"\x06\x05\x2B\x0E\x03\x02\x1A";
				v2->sigPolicyHash.hashAlgorithm.algorithm.size = 7; 

				HASH hb(BCRYPT_SHA1_ALGORITHM);
				hb.hash(v2->sigPolicyId.buf, v2->sigPolicyId.size);
				vector<BYTE> hbb;
				hb.get(hbb);
				v2->sigPolicyHash.hashValue.buf = hbb.data();
				v2->sigPolicyHash.hashValue.size = (DWORD)hbb.size();


				vector<char> ooo;
				auto ec = der_encode(&asn_DEF_SignaturePolicyId,
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
				ca[2].pszObjId = "1.2.840.113549.1.9.16.2.15";
				ca[2].cValue = 1;
				ca[2].rgValue = &b1;

				SignerEncodeInfo.cAuthAttr = 3;
			}

		}

		Signers.push_back(SignerEncodeInfo);

		CERT_BLOB SignerCertBlob;
		SignerCertBlob.cbData = c->cbCertEncoded;
		SignerCertBlob.pbData = c->pbCertEncoded;
		CertsIncluded.push_back(SignerCertBlob);

	}

	for (auto& c : AddCertificates)
	{
		CERT_BLOB SignerCertBlob;
		SignerCertBlob.cbData = c->cbCertEncoded;
		SignerCertBlob.pbData = c->pbCertEncoded;
		CertsIncluded.push_back(SignerCertBlob);
	}

	CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo = { 0 };
	SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
	SignedMsgEncodeInfo.cSigners = (DWORD)Signers.size();
	SignedMsgEncodeInfo.rgSigners = Signers.data();
	SignedMsgEncodeInfo.cCertEncoded = (DWORD)CertsIncluded.size();
	SignedMsgEncodeInfo.rgCertEncoded = CertsIncluded.data();
	SignedMsgEncodeInfo.rgCrlEncoded = NULL;

	auto cbEncodedBlob = CryptMsgCalculateEncodedLength(
		MY_ENCODING_TYPE,     // Message encoding type
		(Params.Attached ? 0 : CMSG_DETACHED_FLAG),                    // Flags
		CMSG_SIGNED,          // Message type
		&SignedMsgEncodeInfo, // Pointer to structure
		NULL,                 // Inner content OID
		(DWORD)sz);
	if (cbEncodedBlob)
	{
		auto hMsg = CryptMsgOpenToEncode(
			MY_ENCODING_TYPE,        // encoding type
			(Params.Attached ? 0 : CMSG_DETACHED_FLAG) | AuthAttr,                    // Flags
			CMSG_SIGNED,             // message type
			&SignedMsgEncodeInfo,    // pointer to structure
			NULL,                    // inner content OID
			NULL);
		if (hMsg)
		{
			// Add the signature
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

					if (Level >= CLEVEL::CADES_T)
					{

						hr = E_FAIL;
						if (hMsg)
						{
							CryptMsgClose(hMsg);
							hMsg = 0;
						}


						// Get the timestamp of the data...
						vector<char> EH;

						hMsg = CryptMsgOpenToDecode(
							MY_ENCODING_TYPE,   // Encoding type
							Params.Attached ? 0 : CMSG_DETACHED_FLAG,                    // Flags
							0,                  // Message type (get from message)
							0,         // Cryptographic provider
							NULL,               // Recipient information
							NULL);
						if (hMsg)
						{
							if (CryptMsgUpdate(
								hMsg,            // Handle to the message
								(BYTE*)Signature.data(),   // Pointer to the encoded BLOB
								cbEncodedBlob,   // Size of the encoded BLOB
								TRUE))           // Last call
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
											auto hrx = TimeStamp(Params.tparams,EH.data(),(DWORD)EH.size(), CR, Params.TSServer);
											if (FAILED(hrx))
											{
												S = false;
												continue;
											}

											// Verify it....
											PCRYPT_TIMESTAMP_CONTEXT re = 0;
											BYTE* b = (BYTE*)CR.data();
											auto sz2 = CR.size();
											auto res = CryptVerifyTimeStampSignature(b, (DWORD)sz2, (BYTE*)EH.data(), (DWORD)EH.size(), 0, &re, 0, 0);

											if (CR.size() && res)
											{
												CRYPT_ATTRIBUTE cat = { 0 };
												cat.cValue = 1;
												CRYPT_ATTR_BLOB bl;
												bl.cbData = (DWORD)CR.size();
												bl.pbData = (BYTE*)CR.data();
												cat.rgValue = &bl;
												cat.pszObjId = TsOid;
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
					}
				}
			}
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
	return hr;
}

