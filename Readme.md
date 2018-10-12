# AdES
A C++ library for Windows to create CAdES-B,CAdES-T,CAdES-C,CAdES-X,CAdES-XL,XAdES-B,XAdES-T,XAdES-C,XAdES-X,XAdES-XL and PAdES-B-T messages. Also supports ASiC-S and ASiC-E with both CAdES and XAdES. 100% ETSI Compliant.

## CAdES
Article at CodeProject: https://www.codeproject.com/script/Articles/ArticleVersion.aspx?waid=267644&aid=1256991

Quick guide:

```C++
HRESULT Sign(LEVEL lev,const char* data,DWORD sz,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params,std::vector<char>& Signature);
HRESULT Verify(const char* data, DWORD sz, LEVEL& lev,const char* omsg = 0,DWORD len = 0,std::vector<char>* msg = 0,std::vector<PCCERT_CONTEXT>* Certs = 0,VERIFYRESULTS* vr = 0);
```

Where
* lev, enumeration from LEVEL: CMS,B,T,C,X or XL
* data/sz, the data to sign
* Certificates, a list of certificates to use for signing. Each CERT contains the certificate, CRLs, and more validation certificates
* Params, additional parameters, including timestamp server, policy, commitment type, attach method etc.

In Verify()
* data/sz, the signature to verify
* lev, gets the detected level
* omsg/len, the original data if the signature was detached
* msg/certs/results, returned message, certificates used, and other data (policy, commitment type etc)


## XAdES
Article at CodeProject: https://www.codeproject.com/script/Articles/ArticleVersion.aspx?waid=268671&aid=1259460

Quick guide:

```C++
struct FILEREF
{
	const char* data = 0; // pointer to data
	DWORD sz = 0; // size, or 0 if null terminated XML
	const char* ref = 0;
	std::string mime = "application/octet-stream";
};
HRESULT XMLSign(LEVEL lev, std::vector<FILEREF>& data,const std::vector<CERT>& Certificates,SIGNPARAMETERS& Params, std::vector<char>& Signature);
```

## PAdES
Article at CodeProject: https://www.codeproject.com/Articles/1262275/The-AdES-Tetralogy-Part-3-PAdES-for-Windows-in-Cpl

Quick guide:

```C++
HRESULT PDFSign(LEVEL lev,const char* data,DWORD sz,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params,std::vector<char>& Signature);
```

## ASiC
Article at CodeProject: https://www.codeproject.com/Articles/1260769/The-AdES-Trilogy-Part-3-ASiC-containers

Quick guide:

```C++
HRESULT ASiC(ALEVEL alev,ATYPE typ, LEVEL lev,std::vector<FILEREF>& data,std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& fndata);
```

