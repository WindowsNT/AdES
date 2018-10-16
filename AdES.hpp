

#include <cryptxml.h>
#include <memory>
#include <tuple>

using namespace std;

class HRESULTERROR
{
public:

	HRESULT hr = 0;
	string err;

	HRESULTERROR(HRESULT hrx, const char* str = "")
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

	template <typename T> T* AddMem(vector<shared_ptr<vector<char>>>& mem, size_t sz = sizeof(T))
	{
		shared_ptr<vector<char>> x = make_shared<vector<char>>();
		x->resize(sz);
		mem.push_back(x);
		T* d = (T*)mem[mem.size() - 1].get()->data();
		return d;
	}

	HRESULT GetEncryptedHash(const char*d, DWORD sz, PCCERT_CONTEXT ctx,CRYPT_ALGORITHM_IDENTIFIER hash,vector<char> &rs);

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

	struct PDFSIGNPARAMETERS
	{
		string Name;
		string Location;
		string Reason;
		string Contact;

		void ClearPars(string& s)
		{
			string a;
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
		wstring TSServer = L"http://timestamp.comodoca.com/";
		string Policy;
		string TSPolicy;
		string commitmentTypeOid;//		1.2.840.113549.1.9.16.6.1 - 6
		vector<CRYPT_ATTRIBUTE> cextras;
		string xextras;
		int Type1OrType2 = 2; // For X and XL forms timestamp, currently 2 is supported, this parameter is ignored
		bool ASiC = false; // True if this is for ASiC
		bool Debug = false;
		bool PAdES = false; // True if PAdES, to eliminate self timestamp
		PDFSIGNPARAMETERS pdfparams;
		
	};

	struct VERIFYRESULT
	{
		string Policy;
		string Commitment;
	};
	struct VERIFYRESULTS
	{
		vector<VERIFYRESULT> Results;
	};

	struct CERTANDCRL
	{
		PCCERT_CONTEXT cert;
		vector<PCCRL_CONTEXT> Crls;
	};
	struct CERT
	{
		CERTANDCRL cert;
		vector<CERTANDCRL> More;
	};

	AdES();

	struct FILEREF
	{
		const char* data = 0; // pointer to data
		DWORD sz = 0; // size, or 0 if null terminated XML
		const char* ref = 0;
		string mime = "application/octet-stream";

		FILEREF(const char * d = 0, DWORD z = 0, const char* rref = 0, const char* mim = 0)
		{
			data = d;
			sz = z;
			ref = rref;
			if (mim)
				mime = mim;
		}
	};

	HRESULT AddCT(vector<char>& Signature, const vector<CERT>& Certificates, SIGNPARAMETERS& Params);
	tuple<HRESULT,vector<char>,vector<char>> AddCC(vector<char>& Signature, const vector<CERT>& Certificates,SIGNPARAMETERS& Params);
	HRESULT AddCX(vector<char>& Signature, const vector<CERT>& Certificates, SIGNPARAMETERS& Params, vector<char>& full1, vector<char >&full2);
	HRESULT AddCXL(vector<char>& Signature, const vector<CERT>& Certificates, SIGNPARAMETERS& Params);

	HRESULT TimeStamp(SIGNPARAMETERS& params,const char* data, DWORD sz, vector<char>& CR, const wchar_t* url = L"http://timestamp.comodoca.com/", const char* alg = szOID_NIST_sha256);
	HRESULT Sign(LEVEL lev,const char* data,DWORD sz,const vector<CERT>& Certificates, SIGNPARAMETERS& Params,vector<char>& Signature);
	HRESULT Verify(const char* data, DWORD sz, LEVEL& lev,const char* omsg = 0,DWORD len = 0,vector<char>* msg = 0,vector<PCCERT_CONTEXT>* Certs = 0,VERIFYRESULTS* vr = 0);
	HRESULT VerifyB(const char* data, DWORD sz, int sidx = 0,bool Attached = true,PCCERT_CONTEXT c = 0);
	HRESULT VerifyT(const char* data, DWORD sz, PCCERT_CONTEXT* pX = 0, bool Attached = true, int TSServerSignIndex = 0, FILETIME* ft = 0);
	HRESULT VerifyU(const char* data, DWORD sz, bool Attached = true, int TSServerSignIndex = 0);
	HRESULT XMLSign(LEVEL lev, vector<FILEREF>& data,const vector<CERT>& Certificates,SIGNPARAMETERS& Params, vector<char>& Signature);

	HRESULTERROR PDFCreateDSSObject(const vector<CERT>& Certificates, int objnum,vector<vector<char>>& r);

	HRESULTERROR PDFSign(LEVEL lev, const char* data, DWORD sz, const vector<CERT>& Certificates, SIGNPARAMETERS& Params, vector<char>& Signature);

	HRESULT ASiC(ALEVEL alev,ATYPE typ, LEVEL lev,vector<FILEREF>& data,vector<CERT>& Certificates, SIGNPARAMETERS& Params, vector<char>& fndata);

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


