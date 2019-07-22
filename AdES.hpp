

#include <cryptxml.h>
#include <memory>
#include <tuple>

//using namespace std;

class HRESULTERROR
{
public:

	HRESULT hr = 0;
	std::string err;

	HRESULTERROR(HRESULT hrx = E_FAIL, const char* str = "")
	{
		hr = hrx;
		if (str)
			err = str;
	}

	operator HRESULT()
	{
		return hr;
	}
};

class AdES
{
private:

	template <typename T> T* AddMem(std::vector<std::shared_ptr<std::vector<char>>>& mem, size_t sz = sizeof(T))
	{
		std::shared_ptr<std::vector<char>> x = std::make_shared<std::vector<char>>();
		x->resize(sz);
		mem.push_back(x);
		T* d = (T*)mem[mem.size() - 1].get()->data();
		return d;
	}

	HRESULT GetEncryptedHash(const char*d, DWORD sz, PCCERT_CONTEXT ctx,CRYPT_ALGORITHM_IDENTIFIER hash, std::vector<char> &rs);
//	HRESULT VerifyEncryptedHash(const char* d, DWORD sz, const char* org, DWORD orgsz);

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


	enum class LEVEL
	{
		CMS = 0,
		XMLDSIG = 0,
		B = 1,
		T = 2,
		C = 3,
		X = 4,
		XL = 5,
		A = 6,
	};

	
	enum class ATTACHTYPE
	{
		DETACHED = 0,
		ENVELOPING = 1,
		ATTACHED = 1,
		ENVELOPED = 2,
	};

	struct PDFSIGNVISIBLE
	{
		std::string t;
		int left = 1;
		int top = 15;
		int fs = 5;
		int wi = 70;
	};

	struct PDFSIGNPARAMETERS
	{
		std::string Name;
		std::string Location;
		std::string Reason;
		std::string Contact;
		PDFSIGNVISIBLE Visible;

		void ClearPars(std::string& s)
		{
			std::string a;
			for (auto& ss : s)
			{
				if (ss != '(' && ss != ')')
					a += ss;
			}
			s = a;
		}
	};

	struct SIGNPARAMETERS
	{
		int ConformanceLevel = 0;
		CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm = { szOID_NIST_sha256 };
		ATTACHTYPE Attached = ATTACHTYPE::ATTACHED;
		std::wstring TSServer = L"http://timestamp.comodoca.com/";
		std::string Policy;
		std::string TSPolicy;
		std::string commitmentTypeOid;//		1.2.840.113549.1.9.16.6.1 - 6
		std::vector<CRYPT_ATTRIBUTE> cextras;
		std::string xextras;
		int Type1OrType2 = 2; // For X and XL forms timestamp, currently 2 is supported, this parameter is ignored
		bool ASiC = false; // True if this is for ASiC
		bool Debug = false;
		bool PAdES = false; // True if PAdES, to eliminate self timestamp
		PDFSIGNPARAMETERS pdfparams;
		bool XMLComments = false;
		
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

	struct FILEREF
	{
		const char* data = 0; // pointer to data
		DWORD sz = 0; // size, or 0 if null terminated XML
		const char* ref = 0;
		std::string mime = "application/octet-stream";

		FILEREF(const char * d = 0, DWORD z = 0, const char* rref = 0, const char* mim = 0)
		{
			data = d;
			sz = z;
			ref = rref;
			if (mim)
				mime = mim;
		}
	};


	struct GREEKRESULTS
	{
		int Type = 0; // 0 none ,1 soft, 2 hard
		int TSThere = 0; // 0 none, 1 generic, 2 greek TSA with policy
		int Level = 0; // Equal to PADES levels
	};
	HRESULT GreekVerifyCertificate(PCCERT_CONTEXT c, const char* sig,DWORD sigsize,GREEKRESULTS& r);
	HRESULT GreekVerifyTimestamp(PCCERT_CONTEXT c, PCRYPT_TIMESTAMP_CONTEXT tc, GREEKRESULTS& r);

	struct PDFVERIFY
	{
		std::vector<char> dx;
		std::vector<char> sig;
		HRESULTERROR S;
		bool Full = false;
		LEVEL l;
		std::vector<PCCERT_CONTEXT> Certs;
		VERIFYRESULTS vr;
	};


	HRESULT AddCT(std::vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params);
	std::tuple<HRESULT,std::vector<char>,std::vector<char>> AddCC(std::vector<char>& Signature, const std::vector<CERT>& Certificates,SIGNPARAMETERS& Params);
	HRESULT AddCX(std::vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& full1, std::vector<char >&full2);
	HRESULT AddCXL(std::vector<char>& Signature, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params);

	HRESULT TimeStamp(SIGNPARAMETERS& params,const char* data, DWORD sz, std::vector<char>& CR, const wchar_t* url = L"http://timestamp.comodoca.com/", const char* alg = szOID_NIST_sha256);
	HRESULT Sign(LEVEL lev,const char* data,DWORD sz,const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params,std::vector<char>& Signature);
	HRESULT Verify(const char* data, DWORD sz, LEVEL& lev,const char* omsg = 0,DWORD len = 0,std::vector<char>* msg = 0,std::vector<PCCERT_CONTEXT>* Certs = 0,VERIFYRESULTS* vr = 0,bool WasPDF = false);
	HRESULT VerifyB(const char* data, DWORD sz, int sidx = 0,bool Attached = true,PCCERT_CONTEXT c = 0,bool WasPDF = false);
	HRESULT VerifyT(const char* data, DWORD sz, PCCERT_CONTEXT* pX = 0, bool Attached = true, int TSServerSignIndex = 0, FILETIME* ft = 0, PCRYPT_TIMESTAMP_CONTEXT* ptc = 0);
	HRESULT VerifyU(const char* data, DWORD sz, bool Attached = true, int TSServerSignIndex = 0);
	HRESULT XMLSign(LEVEL lev, std::vector<FILEREF>& data,const std::vector<CERT>& Certificates,SIGNPARAMETERS& Params, std::vector<char>& Signature);
	HRESULT XMLVerify(const char* xmldata, LEVEL& lev, ATTACHTYPE& att,const char* omsg = 0, DWORD len = 0, bool WasDetachedCanonicalized = false,std::vector<PCCERT_CONTEXT> * Certs = 0, VERIFYRESULTS * vr = 0);

	HRESULTERROR PDFCreateDSSObject(const std::vector<CERT>& Certificates, long long objnum,std::vector<std::vector<char>>& r);

	HRESULTERROR PDFSign(LEVEL lev, const char* data, DWORD sz, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& Signature,std::vector<PDFVERIFY>* = 0);
	HRESULTERROR PDFVerify(const char* d, DWORD sz, std::vector<PDFVERIFY>& VerifyX);

	HRESULTERROR PESign(LEVEL levx, const char* d, DWORD sz, const std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& res);


	HRESULT ASiC(ALEVEL alev,ATYPE typ, LEVEL lev,std::vector<FILEREF>& data,std::vector<CERT>& Certificates, SIGNPARAMETERS& Params, std::vector<char>& fndata);
	struct ASICVERIFY
	{
		bool Full = false;
		ALEVEL alev = ALEVEL::S;
		LEVEL lev = LEVEL::CMS;
		ATYPE atyp = ATYPE::CADES;
		std::vector<PCCERT_CONTEXT> Certs;
		VERIFYRESULTS vr;
		std::vector<std::tuple<std::wstring,HRESULT>> items;
	};
	HRESULT VerifyASiC(const char* data,size_t sz,ASICVERIFY& av);
};


#ifdef _WIN64
#ifdef _DEBUG
#pragma comment(lib,".\\packages\\zlib-msvc14-x64.1.2.11.7795\\build\\native\\lib_debug\\zlibstaticd.lib")
#else
#pragma comment(lib,".\\packages\\zlib-msvc14-x64.1.2.11.7795\\build\\native\\lib_release\\zlibstatic.lib")
#endif

#else
#ifdef _DEBUG
#pragma comment(lib,".\\packages\\zlib-msvc14-x86.1.2.11.7795\\build\\native\\lib_debug\\zlibstaticd.lib")
#else
#pragma comment(lib,".\\packages\\zlib-msvc14-x86.1.2.11.7795\\build\\native\\lib_release\\zlibstatic.lib")
#endif
#pragma comment(lib,"vcruntime.lib")
#endif


