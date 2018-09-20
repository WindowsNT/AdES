# Project Title
A C++ library for Windows to create CAdES-B,CAdES-T,CAdES-C,CAdES-X,CAdES-XL,XAdES-B and XAdES-T messages. Also supports ASiC-S and ASiC-E with CAdES-XL and XAdES-T.

## CAdES
Article at CodeProject: https://www.codeproject.com/script/Articles/ArticleVersion.aspx?waid=267644&aid=1256991

Quick guide:

```C++
	enum class LEVEL
	{
		CMS = 0,
		XMLDSIG = 0,
		B = 1,
		T = 2,
		C = 3,
		X = 4,
		XL = 5,
	};

	
	enum class ATTACHTYPE
	{
		DETACHED = 0,
		ENVELOPING = 1,
		ATTACHED = 1,
		ENVELOPED = 2,
	};

	struct SIGNPARAMETERS
	{
		CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm = { szOID_NIST_sha256 };
		ATTACHTYPE Attached = ATTACHTYPE::ATTACHED;
		const wchar_t* TSServer = L"http://timestamp.comodoca.com/";
		std::string Policy;
		CRYPT_TIMESTAMP_PARA tparams = { 0,TRUE,{},0,0 };
		std::string commitmentTypeOid; //1.2.840.113549.1.9.16.6.1 - 6
		std::string ProductionPlace;
		std::string Role;
		int Type1OrType2 = 2; // For X and XL forms timestamp, currently 2 is supported, this parameter is ignored
		bool ASiC = false; // True if this XAdES is for ASiC
	};

	struct VERIFYRESULT
	{
		std::string Policy;
		std::string Commitment;
	};
	struct VERIFYRESULTS
	{
		std::vector<VERIFYRESULT> Results;
	};

	struct CERTANDCRL
	{
		PCCERT_CONTEXT cert;
		std::vector<PCCRL_CONTEXT> Crls;
	};
	struct CERT
	{
		CERTANDCRL cert;
		std::vector<CERTANDCRL> More;
	};
	HRESULT Sign(LEVEL lev,const char* data,DWORD sz,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params,std::vector<char>& Signature);
	HRESULT Verify(const char* data, DWORD sz, LEVEL& lev,const char* omsg = 0,DWORD len = 0,std::vector<char>* msg = 0,std::vector<PCCERT_CONTEXT>* Certs = 0,VERIFYRESULTS* vr = 0);
```

## XAdES
Article at CodeProject: https://www.codeproject.com/script/Articles/ArticleVersion.aspx?waid=268671&aid=1259460


