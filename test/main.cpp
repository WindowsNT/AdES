#include <cstring>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <ctime>
#include <windows.h>
#include <cryptdlg.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <cryptuiapi.h>
#include <vector>

#pragma comment(lib,"Cryptui.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma comment(lib,"..\\AdES.lib")
#include "..\\AdES.hpp"

#include "..\\xml\\xml3all.h"

using namespace std;
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

template <typename T = char>
inline bool PutFile(const wchar_t* f, vector<T>& d)
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

static
PCCERT_CONTEXT
HrGetSigner(
	LPCWSTR                 wszSubject = 0)
{
	HCERTSTORE      hStore = NULL;
	PCCERT_CONTEXT  pCert = NULL;

	//
	// Open the local user store to search for certificates
	//

	hStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM_W,
		X509_ASN_ENCODING,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
		L"MY"
	);


	if (NULL != wszSubject && 0 != *wszSubject)
	{
		//
		// Search by Name
		//

		while (NULL != (pCert = CertFindCertificateInStore(
			hStore,
			X509_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_STR,
			wszSubject,
			pCert
		)))
		{
			CertCloseStore(hStore,0);
			return pCert;
		}
	}
	else
	{
		//
		// Get the first available certificate in the store
		//

		while (NULL != (pCert = CertEnumCertificatesInStore(
			hStore,
			pCert
		)))
		{
			CertCloseStore(hStore, 0);
			return pCert;
		}
	}
}


int main()
{
	vector<char> hellox;


	// Load the file
	vector<char> hello;
	LoadFile(L"..\\hello.txt", hello);
	char* msg = hello.data();
	size_t b = hello.size();
	AdES a;
	std::vector<PCCERT_CONTEXT> Certs;
	AdES::SIGNPARAMETERS Params;
	vector<PCCERT_CONTEXT> More;
	
/*	for(;;)
	{

		PCCERT_CONTEXT cert = 0;
		auto hStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM_W,
			X509_ASN_ENCODING,
			NULL,
			CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
			L"MY");
		cert = CryptUIDlgSelectCertificateFromStore(hStore, 0, 0, 0, 0, 0, 0);
		if (!cert)
			break;
		Certs.push_back(cert);
		// Ánd all the chain
		PCCERT_CHAIN_CONTEXT CC = 0;
		CERT_CHAIN_PARA CCP = { 0 };
		CCP.cbSize = sizeof(CCP);
		CCP.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
		CERT_ENHKEY_USAGE        EnhkeyUsage = { 0 };
		CCP.RequestedUsage.Usage = EnhkeyUsage;
		CertGetCertificateChain(0, cert, 0, 0, &CCP, 0, 0, &CC);
		if (CC)
		{
			for (DWORD i = 0; i < CC->cChain; i++)
			{
				PCERT_SIMPLE_CHAIN ccc = CC->rgpChain[i];
				for (DWORD ii = 0; ii < ccc->cElement; ii++)
				{
					PCERT_CHAIN_ELEMENT el = ccc->rgpElement[ii];
					// Dup check
					bool D = false;
					for (auto& ec : Certs)
					{
						if (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ec->pCertInfo, el->pCertContext->pCertInfo))
						{
							D = true;
						}
					}
					for (auto& ec : More)
					{
						if (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ec->pCertInfo, el->pCertContext->pCertInfo))
						{
							D = true;
						}
					}
					if (!D)
						More.push_back(el->pCertContext);
				}
			}
		}
		if (MessageBox(0, L"Add more signatures?", L"", MB_YESNO) == IDNO)
			break;
	}
	*/
	Certs.push_back(HrGetSigner(L"ch.michael@cyta.gr"));


	if (Certs.empty())
		return 0;

	std::vector<char> Sig;
//	Params.Attached = false;
	Params.Policy = "1.3.6.1.5.5.7.48.1";
	Params.commitmentTypeOid = "1.2.840.113549.1.9.16.6.1";
	auto hr1 = a.Sign(AdES::CLEVEL::CADES_T, msg, (DWORD)b, Certs, More, Params,Sig);
	PutFile(L"..\\hello2.p7m", Sig);
	AdES::CLEVEL lev;
	vector<PCCERT_CONTEXT> CV;
	vector<char> dmsg;
	AdES::VERIFYRESULTS v;
	auto hr3 = a.Verify(Sig.data(), (DWORD)Sig.size(), lev, 0, 0, &dmsg, &CV, &v);

	Sig.clear();
	LoadFile(L"..\\hello.xml", hellox);
	hellox.resize(hellox.size() + 1);
	//Params.HashAlgorithm.pszObjId = szOID_OIWSEC_sha1;

	//auto hr2 = a.XMLSign(AdES::XLEVEL::XMLDSIG, AdES::XTYPE::ENVELOPED, 0,hellox.data(), Certs, More, Params, Sig);
	auto hr2 = a.XMLSign(AdES::XLEVEL::XADES_T,AdES::XTYPE::ENVELOPED, 0, hellox.data(), Certs, More, Params, Sig);
	PutFile(L"..\\hello2.xml", Sig);

	tuple<const BYTE*, DWORD, const char*> t1 = std::make_tuple<const BYTE*, DWORD, const char*>(
		std::forward<const BYTE*>((BYTE*)hellox.data()), 
		hellox.size() - 1, 
		std::forward<const char*>((const char*)"hello.xml"));
	vector<tuple<const BYTE*, DWORD, const char*>> tx = { t1 };
	auto hr4 = a.ASiC(AdES::ALEVEL::S, AdES::ATYPE::XADES, tx, Certs, More, Params, Sig);
	PutFile(L"..\\hello2.asics", Sig);

/*
	LoadFile(L"..\\hello2.xml", hellox);
	hellox.resize(hellox.size() + 1);
	hr2 = a.XMLSign(AdES::XLEVEL::XADES_B, AdES::XTYPE::ENVELOPED, hellox.data(), Certs, More, Params, Sig);
	PutFile(L"..\\hello2.xml", Sig);
*/

	// Free Certificates in Production Code...
}