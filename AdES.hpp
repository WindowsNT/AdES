

#include <cryptxml.h>
#include <memory>



class AdES
{
private:

	char* TsOid = "1.2.840.113549.1.9.16.2.14";

	template <typename T> T* AddMem(std::vector<std::shared_ptr<std::vector<char>>>& mem, size_t sz = sizeof(T))
	{
		shared_ptr<vector<char>> x = make_shared<vector<char>>();
		x->resize(sz);
		mem.push_back(x);
		T* d = (T*)mem[mem.size() - 1].get()->data();
		return d;
	}

	HRESULT GetEncryptedHash(const char*d, DWORD sz, PCCERT_CONTEXT ctx,CRYPT_ALGORITHM_IDENTIFIER hash,std::vector<char> &rs);

public:

	enum class ALEVEL
	{
		S = 0,
		E = 1,
	};

	enum class ATYPE
	{
		CADES = 0,
		XADES = 1
	};


	enum class CLEVEL
	{
		CMS = 0,
		CADES_B=1,
		CADES_T=2,
		CADES_C=3
	};

	enum class XLEVEL
	{
		XMLDSIG = 0,
		XADES_B = 1,
		XADES_T = 2
	};

	enum class XTYPE
	{
		DETACHED = 0,
		ENVELOPED = 2,
	};

	struct SIGNPARAMETERS
	{
		CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm = { szOID_NIST_sha256 };
		bool Attached = true;
		const wchar_t* TSServer = L"http://timestamp.comodoca.com/";
		std::string Policy;
		CRYPT_TIMESTAMP_PARA tparams = { 0,TRUE,{},0,0 };
		std::string commitmentTypeOid;
		std::string ProductionPlace;
		std::string Role;
		/*
		1.2.840.113549.1.9.16.6.1 - 6


		*/
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

	AdES();
	HRESULT TimeStamp(CRYPT_TIMESTAMP_PARA params,const char* data, DWORD sz, std::vector<char>& CR, const wchar_t* url = L"http://timestamp.comodoca.com/", const char* alg = szOID_NIST_sha256);
	HRESULT Sign(CLEVEL lev,const char* data,DWORD sz,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params,std::vector<char>& Signature);
	HRESULT Verify(const char* data, DWORD sz, CLEVEL& lev,const char* omsg = 0,DWORD len = 0,std::vector<char>* msg = 0,std::vector<PCCERT_CONTEXT>* Certs = 0,VERIFYRESULTS* vr = 0);
	HRESULT VerifyB(const char* data, DWORD sz, int sidx = 0,bool Attached = true,PCCERT_CONTEXT c = 0);
	HRESULT VerifyT(const char* data, DWORD sz, PCCERT_CONTEXT* pX = 0, bool Attached = true, int TSServerSignIndex = 0, FILETIME* ft = 0);
	HRESULT XMLSign(XLEVEL lev, XTYPE typ,const char* URIRef,const char* data, const std::vector<CERT>& Certificates,SIGNPARAMETERS& Params, std::vector<char>& Signature);

	HRESULT ASiC(ALEVEL lev,ATYPE typ, std::vector<std::tuple<const BYTE*,DWORD,const char*>>& data,std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& fndata);

};

