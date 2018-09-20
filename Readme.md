# Project Title
A C++ library for Windows to create CAdES-B,CAdES-T,CAdES-C,CAdES-X,CAdES-XL,XAdES-B and XAdES-T messages. Also supports ASiC-S and ASiC-E with CAdES-XL and XAdES-T.

## CAdES
Article at CodeProject: https://www.codeproject.com/script/Articles/ArticleVersion.aspx?waid=267644&aid=1256991

Quick guide:

```C++
	HRESULT Sign(LEVEL lev,const char* data,DWORD sz,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params,std::vector<char>& Signature);
	HRESULT Verify(const char* data, DWORD sz, LEVEL& lev,const char* omsg = 0,DWORD len = 0,std::vector<char>* msg = 0,std::vector<PCCERT_CONTEXT>* Certs = 0,VERIFYRESULTS* vr = 0);
```

## XAdES
Article at CodeProject: https://www.codeproject.com/script/Articles/ArticleVersion.aspx?waid=268671&aid=1259460

Quick guide:

```C++
	HRESULT XMLSign(LEVEL lev, std::vector<std::tuple<const BYTE*, DWORD, const char*>>& data,const std::vector<CERT>& Certificates,SIGNPARAMETERS& Params, std::vector<char>& Signature);
```

## ASiC
Article at CodeProject: Pending

Quick guide:

```C++
	HRESULT ASiC(ALEVEL alev,ATYPE typ, LEVEL lev,std::vector<std::tuple<const BYTE*,DWORD,const char*>>& data,std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& fndata);
```

