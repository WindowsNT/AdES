


#ifdef _WIN64
#include ".\\packages\\zlib-msvc14-x86.1.2.11.7795\\build\\native\\include\\zlib.h"
#else
#include ".\\packages\\zlib-vc140-static-64.1.2.11\\lib\\native\\include\\zlib.h"
#endif



namespace PDF
{


	// astring class
	class astring : public std::string
	{
	public:
		astring& Format(const char* f, ...)
		{
			va_list args;
			va_start(args, f);

			int len = _vscprintf(f, args) + 100;
			if (len < 8192)
				len = 8192;
			vector<char> b(len);
			vsprintf_s(b.data(), len, f, args);
			assign(b.data());
			va_end(args);
			return *this;
		}

		astring trim()
		{
			auto ec = [](char c)
			{
				if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
					return true;
				return false;

			};
			astring t = *this;
			while (t.length() && ec(t[0]))
				t.erase(t.begin());
			while (t.length() && ec(t[t.length() - 1]))
				t.erase(t.end() - 1);	
			return t;
		}
		astring() : string() {}
		astring(const char*s) : string(s) {}
	};

	template <typename T>
	void AddCh(vector<char>& s, T& s2)
	{
		auto os = s.size();
		s.resize(s.size() + s2.length());
		memcpy(s.data() + os, s2.data(), s2.length());
	}
	inline void AddCh(vector<char>& s, const char* s2)
	{
		auto os = s.size();
		s.resize(s.size() + strlen(s2));
		memcpy(s.data() + os, s2, strlen(s2));
	}

	inline long long memstr(const char* arr, long long length, const char* tofind, long long flength) {
		for (long long i = 0; i < length - flength; ++i) {
			if (memcmp(arr + i, tofind, flength) == 0)
				return i;
		}
		return (long long)-1;
	}

	inline long long memrstr(const char* arr, long long length, const char* tofind, long long flength) {
		for (long long i = (length - flength); i >= 0; --i) {
			if (memcmp(arr + i, tofind, flength) == 0)
				return i;
		}
		return (long long)-1;
	}

	inline std::vector<std::string>& split(const std::string &s, char delim, std::vector<std::string> &elems) {
		std::stringstream ss(s);
		std::string item;
		while (std::getline(ss, item, delim))
		{
			elems.push_back(item);
		}
		return elems;
	}


	inline std::vector<std::string> split(const std::string &s, char delim) {
		std::vector<std::string> elems;
		split(s, delim, elems);
		return elems;
	}

	inline string upoline(const char*& st, unsigned long long& i)
	{
		string a;
		if (!st)
			return a;

		for (;;)
		{
			if (*st == '%' || *st == '\x0a' || *st == '\x0d')
			{
				bool c = false;
				if (*st == '%')
					c = true;
				i++;
				while (*st == '\x0a' || *st == '\x0d' || c)
				{
					if (*st == '\x0a' || *st == '\x0d')
						c = false;

					st++;
					i++;
				}
				
				return a;
			}
			a += *st;
			i++;
			st++;
		}
	}

	inline string BinToHex(const unsigned char* d, long long sz)
	{
		string a;
		char f[30] = { 0 };
		for (long long i = 0; i < sz; i++)
		{
			sprintf_s(f, 30, "%02X", d[i]);
			a += f;
		}
		return a;
	}

	inline void HexToBin(string hex, vector<char>& d)
	{
		char f[30];
		d.resize(hex.length() / 2);

		for (long long i = 0; i < hex.length(); i += 2)
		{
			int c = 0;
			f[0] = '0';
			f[1] = 'x';
			f[2] = hex[i];
			f[3] = hex[i + 1];
			sscanf_s(f, "%02X", &c);

			d[i / 2] = (char)c;
		}
	}

	enum class INXTYPE
	{
		TYPE_NONE = 0,
		TYPE_DIC = 1,
		TYPE_NAME = 2,
		TYPE_ARRAY = 3,
		TYPE_STRING = 4,
	};

	class INX
	{
	public:
		INXTYPE Type = INXTYPE::TYPE_NONE;
		INX* Par = 0;
		astring Name;
		astring Value;
		list<INX> Contents;


		void Serialize(vector<char>& d)
		{
			if (Type == INXTYPE::TYPE_DIC)
			{
				astring str;
				if (Contents.empty())
				{
					str.Format("<<%s>>", Value.trim().c_str());
					AddCh(d, str);
				}
				else
				{
					str.Format("<<%s", Value.trim().c_str());
					AddCh(d, str);
					for (auto& c : Contents)
						c.Serialize(d);
					str.Format(">>");
					AddCh(d, str);
				}
			}
			else
			if (Type == INXTYPE::TYPE_ARRAY)
			{
				astring str;
				if (Contents.empty())
				{
					str.Format("[%s]", Value.trim().c_str());
					AddCh(d, str);
				}
				else
				{
					str.Format("[%s", Value.trim().c_str());
					AddCh(d, str);
					for (auto& c : Contents)
						c.Serialize(d);
					str.Format("]");
					AddCh(d, str);
				}
			}
			else
			if (Type == INXTYPE::TYPE_STRING)
			{
				astring str;
				if (Contents.empty())
				{
					str.Format("(%s)", Value.c_str());
					AddCh(d, str);
				}
				else
				{

/*					str.Format("(%s", Value.c_str());
					AddCh(d, str);
					for (auto& c : Contents)
						c.Serialize(d);
					str.Format(")");
					AddCh(d, str);
*/
				}
			}
			else
			if (Type == INXTYPE::TYPE_NAME)
			{
				astring str;
				if (Contents.empty())
				{
					if (Name.trim().empty())
						str.Format("/%s", Value.trim().c_str());
					else
					if (Value.trim().empty())
						str.Format("/%s", Name.trim().c_str());
					else
						str.Format("/%s %s", Name.trim().c_str(), Value.trim().c_str());
					AddCh(d, str);
				}
				else
				{
					if (Name.trim().empty())
						str.Format("/%s", Value.trim().c_str());
					else
					if (Value.trim().empty())
						str.Format("/%s", Name.trim().c_str());
					else
						str.Format("/%s %s", Name.trim().c_str(), Value.trim().c_str());
					AddCh(d, str);
					for (auto& c : Contents)
						c.Serialize(d);
				}
			}
			else
				DebugBreak();
		}
	};

	class OBJECT
	{
	public:

		unsigned long long p = 0;
		unsigned long long num = 0;
		bool q = false;
		INX content;

		// For stream
		unsigned long long str_pos = 0;
		unsigned long long str_size = 0;


		HRESULTERROR Parse2(unsigned long long nu,const char *d,bool NoUp = false)
		{
			auto orgd = d;
			INX* n = &content;
			num = nu;
			unsigned long long i = 0;
			if (nu == (unsigned long long)-1)
			{
				nu = atoi(d);
				num = nu;
				auto rz = memstr(d, 100, "obj", 3);
				if (rz == -1)
					return E_FAIL;
				d += rz + 3;
				while (d[0] == '\r' || d[0] == '\n' || d[0] == ' ')
					d++;
				if (d[0] == '%')
				{
					while (d[0] != '\r' && d[0] != '\n')
						d++;
					while (d[0] == '\r' || d[0] == '\n')
						d++;
				}
				NoUp = true;
			}

			if (NoUp == false && nu != 0) // 0 -> trailer
				upoline(d, i);

			auto EndT2 = [&]()
			{
				if (n->Type == INXTYPE::TYPE_NAME)
				{
					if (n->Name.empty())
					{
						n->Name = n->Value;
						n->Value.clear();
					}
					if (n->Name == "Length")
						str_size = atoll(n->Value.c_str());
					n = n->Par;
					if (!n)
						return false;
				}
				return true;
			};

			auto Add = [&](INXTYPE Ty)
			{
				if (n == &content && n->Type == INXTYPE::TYPE_NONE)
				{
					n->Type = Ty;
				}
				else
				{
					INX n2;
					n2.Type = Ty;
					n2.Par = n;
					n->Contents.push_back(n2);
					n = &n->Contents.back();
				}
			};

			for (;;)
			{
				if (!d)
					break;
				if (d[0] == 0)
					break;

				if (d[0] == '<' && d[1] == '<' &&  n->Type != INXTYPE::TYPE_STRING)
				{
					//if (!EndT2()) break;
					d += 2;
					Add(INXTYPE::TYPE_DIC);
					continue;
				}

				if (d[0] == '>' && d[1] == '>' &&  n->Type != INXTYPE::TYPE_STRING)
				{
					d += 2;
					if (!EndT2()) break;
					if (n->Type == INXTYPE::TYPE_DIC)
					{
						n = n->Par;
						if (!n || n == &content)
							break;
						continue;
					}
				}
				if (d[0] == '[' && n->Type != INXTYPE::TYPE_STRING)
				{
					d += 1;
					Add(INXTYPE::TYPE_ARRAY);
					continue;
				}

				if (d[0] == ']' && n->Type != INXTYPE::TYPE_STRING)
				{
					d += 1;
					if (!EndT2()) break;
					if (n->Type == INXTYPE::TYPE_ARRAY)
					{
						n = n->Par;
						if (!n || n == &content)
							break;
						continue;
					}
				}

				if (d[0] == '(' && *(d - 1) != '\\')
				{
					d += 1;
					Add(INXTYPE::TYPE_STRING);
					continue;
				}

				if (d[0] == ')' && *(d - 1) != '\\' && n->Type == INXTYPE::TYPE_STRING)
				{
					d += 1;
					if (n->Type == INXTYPE::TYPE_STRING)
					{
						n = n->Par;
						if (!n || n == &content)
							break;
						continue;
					}
				}

				if (d[0] == '/' && n->Type != INXTYPE::TYPE_STRING)
				{
					if (!EndT2()) break;
					d += 1;
					Add(INXTYPE::TYPE_NAME);
					continue;
				}
/*				if (d[0] == '\r' || d[0] == '\n')
					;
				else*/
				{
					if (n->Type == INXTYPE::TYPE_NAME && n->Name.empty() && (d[0] == ' ' || d[0] == '\n' || d[0] == '\r'))
					{
						n->Name = n->Value;
						n->Value.clear();
					}
					else
						n->Value += *d;
				}
				d++;
			}
			// Check stream
			
			if (memcmp(d, "stream", 6) == 0)
			{
				upoline(d, i);
				str_pos = d - orgd;
			}
			return S_OK;
		}

	};

	class XREF
	{
	public:
		unsigned long long p = 0;
		map<unsigned long long, tuple<bool,unsigned long long>> refs;
		OBJECT if_object;

		vector<tuple<unsigned long long, unsigned long long>> compressedrefs;


		unsigned long long mmax()
		{
			unsigned long long mm = 0;
			for (auto& obj : refs)
			{
				auto num = obj.first;
				if (num > mm)
					mm = num;
			}
			return mm;
		}



		HRESULTERROR XParse(const class DOC&,const char *d,OBJECT& trl)
		{
			unsigned long long i = 0;
			string xrtag = upoline(d, i);
			if (xrtag != "xref")
				return HRESULTERROR(E_UNEXPECTED,"No xref tag");
			unsigned long long  WaitN = 0;
			unsigned long long  Start = 0;
			for (;;)
			{
				if (WaitN == 0)
				{
					string h = upoline(d, i);
					if (h == "trailer")
					{
						trl.p = i;
						trl.Parse2(0, d);
						break;
					}
					auto r = split(h, ' ');
					if (r.size() != 2)
						return false;
					Start = atoll(r[0].c_str());
					WaitN = atoll(r[1].c_str());

					for (auto e = Start; e < (Start + WaitN); e++)
					{
						string t = upoline(d, i);
						auto rr = split(t, ' ');
						if (rr.size() != 3)
							return HRESULTERROR(E_UNEXPECTED, "No 3 size in W");

						auto Ref = atoll(rr[0].c_str());
						if (rr[2] == "n")
							refs[e] = make_tuple<>(true, Ref);
						else
							refs[e] = make_tuple<>(false, Ref);
					}
					WaitN = 0;
				}
			}
			return S_OK;
		}
	};


	class DOC
	{
	public:
		unsigned long long p = 0;
		vector<OBJECT> objects;
		XREF xref;
		OBJECT trailer;


		OBJECT* findobject(long long num)
		{
			OBJECT* d = 0;
			for (auto& o : objects)
			{
				if (o.num == num)
				{
					d = &o;
					return d;
				}
			}
			return 0;
		}

		INX* findname(INX*d,string Name, long long* iIdx = 0, bool R = false)
		{
			if (!d)
				return 0;
			if (d->Type == INXTYPE::TYPE_DIC)
			{
				long long ii = 0;
				for (auto& tt : d->Contents)
				{
					if (tt.Type == INXTYPE::TYPE_NAME && tt.Name == Name)
						if (tt.Type == INXTYPE::TYPE_NAME && tt.Name == Name)
						{
							if (iIdx)
								*iIdx = ii;
							return &tt;
						}
					ii++;
				
				}
			}
			if (!R)
				return 0;
			long long jj = 0;
			for (auto& cc : d->Contents)
			{
				auto ifo = findname(&cc, Name, iIdx, R);
				if (ifo)
					return ifo;
				jj++;
			}
			return 0;

		}

		long long root()
		{
			if (trailer.content.Type == INXTYPE::TYPE_DIC)
			{
				for (auto& tt : trailer.content.Contents)
				{
					if (tt.Type == INXTYPE::TYPE_NAME && tt.Name == "Root")
					{
						auto r = atoll(tt.Value.c_str());
						return r;
					}
				}
			}

			// Check in xref
			auto fn = findname(&xref.if_object.content, "Root", 0, true);
			if (fn)
			{
				auto r = atoll(fn->Value.c_str());
				return r;

			}
			return -1;
		}

		long long size()
		{
			if (trailer.content.Type == INXTYPE::TYPE_DIC)
			{
				for (auto& tt : trailer.content.Contents)
				{
					if (tt.Type == INXTYPE::TYPE_NAME && tt.Name == "Size")
					{
						auto r = atoll(tt.Value.c_str());
						return r;
					}
				}
			}

			// Check in xref
			auto fn = findname(&xref.if_object.content, "Size", 0, true);
			if (fn)
			{
				auto r = atoll(fn->Value.c_str());
				return r;

			}
			return -1;
		}

		INX* GetID()
		{
			if (trailer.content.Type == INXTYPE::TYPE_DIC)
			{
				for (auto& tt : trailer.content.Contents)
				{
					if (tt.Type == INXTYPE::TYPE_NAME && tt.Name == "ID")
					{
						return &tt;
					}
				}
			}

			// Check in xref
			auto fn = findname(&xref.if_object.content, "ID", 0, true);
			if (fn)
				return fn;
			return 0;
		}

		long long info()
		{
			if (trailer.content.Type == INXTYPE::TYPE_DIC)
			{
				for (auto& tt : trailer.content.Contents)
				{
					if (tt.Type == INXTYPE::TYPE_NAME && tt.Name == "Info")
					{
						auto r = atoll(tt.Value.c_str());
						return r;
					}
				}
			}

			// Check in xref
			auto fn = findname(&xref.if_object.content, "Info", 0, true);
			if (fn)
			{
				auto r = atoll(fn->Value.c_str());
				return r;

			}
			return -1;
		}

	};

	class PDF
	{
	public:

		const char* d = 0;
		unsigned long long sz = 0;
		unsigned long long maxobjectnum = 0;
		vector<DOC> docs;
		bool XRefAsObject = false;


		long long root()
		{
			if (docs.empty())
				return -1;
			auto& last = docs[0];
			return last.root();
		}

		long long info()
		{
			if (docs.empty())
				return -1;
			auto& last = docs[0];
			return last.info();
		}


		OBJECT* findobject(long long num)
		{
			for (auto& doc : docs)
			{
				OBJECT* dd = doc.findobject(num);
				if (dd)
					return dd;
			}
			return 0;
		}

		INX* findname(INX* dd, string Name, long long* iIdx = 0,bool R = false)
		{
			if (!dd)
				return 0;
			if (dd->Type == INXTYPE::TYPE_DIC)
			{
				long long ii = 0;
				for (auto& tt : dd->Contents)
				{
					if (tt.Type == INXTYPE::TYPE_NAME && tt.Name == Name)
					{
						if (iIdx)
							*iIdx = ii;
						return &tt;
					}
					ii++;
				}
			}
			if (!R)
				return 0;
			for (auto& cc : dd->Contents)
			{
				auto ifo = findname(&cc, Name, iIdx,R);
				if (ifo)
					return ifo;
			}
			return 0;
		}


		INX* findname(OBJECT* dd, string Name, long long* iIdx = 0,bool R = false)
		{
			if (!dd)
				return 0;
			return findname(&dd->content, Name, iIdx,R);
		}

		unsigned long long mmax()
		{
			unsigned long long mm = 0;
			for (auto& doc : docs)
			{
				auto num = doc.xref.mmax();
				if (num > mm)
					mm = num;
			}
			return mm;
		}


		string PDFVersion;
		HRESULTERROR Parse2(const char* dd, unsigned long long s)
		{
			if (!dd)
				return E_POINTER;
			d = dd;
			sz = s;
			const char* ss = dd;
			if (strncmp(ss, "%PDF-", 5) != 0)
				return HRESULTERROR(E_UNEXPECTED,"No header");
			ss += 5;
			unsigned long long i = 5;
			string f = upoline(ss, i);
			PDFVersion = f;

			auto sss = s;

			unsigned long long PreviousXRefIfXRefIsObject = 0;

			for (;;)
			{
				DOC doc;

				auto peof = memrstr(dd, sss, "%%EOF", 5);
				if (peof == -1)
					break;

				auto startxref = memrstr(dd, peof, "startxref", 9);
				if (startxref == -1)
					return HRESULTERROR(E_UNEXPECTED, "No startxref found");

				ss = dd + startxref;
				f = upoline(ss, i);
				doc.xref.p = atoll(upoline(ss, i).c_str());
				if (doc.xref.p == 0)
				{
					doc.xref.p = PreviousXRefIfXRefIsObject;
					if (doc.xref.p == 0)
						break;
				}

				//sss = doc.xref.p;
				sss = peof - 1;

				bool XrefAsObject = 0;
				auto hrxref = doc.xref.XParse(doc, dd + doc.xref.p, doc.trailer);
				if (hrxref == E_UNEXPECTED)
				{
					XrefAsObject = 1;
					hrxref = ParseXrefAsObject(doc, dd + doc.xref.p, doc.trailer);
					if (SUCCEEDED(hrxref))
						XRefAsObject = true;
				}

				if (hrxref != S_OK)
					break;// return HRESULTERROR(E_UNEXPECTED, "Could not parse XREF entries");

				for (auto& obj : doc.xref.refs)
				{
					auto s2 = obj.second;
					auto num = obj.first;
					if (get<0>(s2) == false)
					{
						OBJECT o;
						o.p = 0;
						o.num = num;
						doc.objects.push_back(o);
						continue;
					}
					OBJECT o;
//					if (XrefAsObject)
						num = (unsigned long long)-1;
					o.p = get<1>(s2);
					o.Parse2(num, dd + get<1>(s2));
					doc.objects.push_back(o);
				}

				auto expandobjstm = [](const char* d,DOC& doc,OBJECT* obj,bool NoDup = false) -> bool
				{
					if (obj->str_size == 0)
						return false;

					// Decompress Stream
					vector<char> uncs(1048576);
					unsigned long destlen = (uLong)uncs.size();
					auto ures = uncompress((Bytef*)uncs.data(), &destlen, (Bytef*)d + (obj->p + obj->str_pos),(uLong) obj->str_size);
					if (ures != 0)
						return false;
					const char* unp = uncs.data();

					map<unsigned long long, unsigned long long> newmaps;
					for (;;)
					{
						int a = atoi(unp);
						if (a == 0)
							break;
						while (unp[0] != ' ')
							unp++;
						while (unp[0] == ' ')
							unp++;
						int b = atoi(unp);
						while (unp[0] != ' ')
							unp++;
						while (unp[0] == ' ')
							unp++;

						newmaps[a] = b;
					}

					for (auto& np : newmaps)
					{
						OBJECT o;
						o.p = 0;
						if (NoDup && doc.findobject(np.first))
							continue;
						o.Parse2(np.first, unp + np.second, true);
						doc.objects.push_back(o);
					}

					return true;
				};

				// And compressed objects by xref
				map<unsigned long long, bool> hasfound;
				for (auto& dr : doc.xref.compressedrefs)
				{
					unsigned long long num = get<0>(dr);
					if (hasfound[num])
						continue;
					hasfound[num] = true;
					auto obj = doc.findobject(num);
					if (!obj)
						continue;
					expandobjstm(d, doc,obj);
				}

				if (maxobjectnum < doc.xref.mmax())
					maxobjectnum = doc.xref.mmax();

				// And also all objects that have a Type /ObjStm
				for (auto& obj : doc.objects)
				{
					auto n2 = findname(&obj, "XRef");
					if (n2)
						expandobjstm(d, doc, &obj, true);
					auto n1 = findname(&obj, "ObjStm");
					if (n1)
						expandobjstm(d, doc, &obj, true);
				}

				// Previous note?
				
				
				PreviousXRefIfXRefIsObject = 0;
				auto npr = findname(&doc.xref.if_object, "Prev");
				if (npr)
				{
					PreviousXRefIfXRefIsObject = atoll(npr->Value.c_str());
				}
				if (!npr)
					npr = findname(&doc.trailer, "Prev");
				if (npr)
				{
					PreviousXRefIfXRefIsObject = atoll(npr->Value.c_str());
				}


				for (auto& obj : doc.objects)
				{
					if (obj.num > maxobjectnum)
						maxobjectnum = obj.num;
				}

				docs.push_back(doc);
			}


			if (docs.empty())
				return S_FALSE;

			return S_OK;
		}

		HRESULTERROR ParseXrefAsObject(DOC& doc, const char *d, OBJECT& trl)
		{
			UNREFERENCED_PARAMETER(trl);
			OBJECT& o = doc.xref.if_object;
			auto zr = o.Parse2(-1, d);
			if (FAILED(zr))
				return zr;


			if (o.str_size == 0)
				return HRESULTERROR(E_UNEXPECTED, "No stream in XrefAsObject");

			// Decompress Stream
			vector<char> uncs(1048576);
			unsigned long destlen = (uLong)uncs.size();
			auto ures  = uncompress((Bytef*)uncs.data(), &destlen,(Bytef*) d + o.str_pos, (uLong)o.str_size);
			if (ures != 0)
				return HRESULTERROR(E_FAIL, "Could not uncompress compressed XREF");

			// Type PNG support
			int PredVal = 0;

			auto prd = doc.findname(&o.content, "Predictor",0,true);
			if (prd)
			{
				PredVal = atoi(prd->Value.c_str());
			}
			if (PredVal < 10 && PredVal > 1)
				return HRESULTERROR(E_FAIL, "Predictor < 10 in compressed XREF");

			// Widths
			auto cw = doc.findname(&o.content, "W", 0, true);
			if (!cw)
				return HRESULTERROR(E_FAIL, "No W found in XREF");
			if (cw->Contents.size() == 0)
				return HRESULTERROR(E_FAIL, "No W contents in XREF");
			if (cw->Contents.front().Type != INXTYPE::TYPE_ARRAY)
				return HRESULTERROR(E_FAIL, "No array contect in W");

			auto widths = cw->Contents.front().Value;
			auto r = split(widths.c_str(), ' ');
			if (r.size() != 3)
				return HRESULTERROR(E_FAIL, "Invalid W array in XREF");

			// Support [1,X,1] currently up to [1,8,1]
			int wi1 = atoi(r[0].c_str());
			int wi2 = atoi(r[1].c_str());
			int wi3 = atoi(r[2].c_str());

			if (wi1 != 1)
				return HRESULTERROR(E_FAIL, "Invalid W array in XREF");
			if (wi2 > 8)
				return HRESULTERROR(E_FAIL, "Invalid W array in XREF");
//			if (wi3 != 1)
	//			return HRESULTERROR(E_FAIL, "Invalid W array in XREF");


			int width = 0;
			for (auto& rr : r)
			{
				width += atoi(rr.c_str());
			}

			// Strip last 10, is CRC (if Predictor is used)
			if (PredVal >= 10)
				destlen -= 10;

			// Loop rows (width value = width + 1)
			vector<unsigned char> PrevRow(width);
			
			unsigned long long jidx = 0;

			for (long long	 p = 0 ; ;)
			{
				const char* dd = uncs.data() + p;

				// Strip first \x02.
				if (PredVal > 10)
				{
					p++;
					dd++;
				}

				unsigned long long RefType = 0;
				unsigned long long RefOfs = 0;
				unsigned long long RefGen = 0;
				int eb1 = 0;
				int eb2 = 0;
				int eb3 = 0;

				for (int row = 0; row < width ; row++)
				{
					unsigned char by = dd[row];
					if (PredVal > 10)
					{
						by += PrevRow[row];
						PrevRow[row] = by;
					}

					if (row == 0)
					{
						eb2 = 8* ( wi2 - 1);
						eb3 = 8 * (wi3 - 1);
						RefType = by;
						RefOfs = 0;
					}
					if (row >= 1 && row < (width - wi3))
					{
						unsigned long long s2 = by;
						unsigned long long r = eb2;
						RefOfs |= (s2 << r);
						eb2 -= 8;
					}
					if (row >= (width - wi3))
					{
						unsigned long long s2 = by;
						unsigned long long r = eb3;
						RefGen |= (s2 << r);
						eb3 -= 8;
					}
				}

				auto& refs = doc.xref.refs;

				if (RefType == 0)
					refs[jidx] = make_tuple<>(false, RefOfs);
				if (RefType == 1)
					refs[jidx] = make_tuple<>(true, RefOfs);
				if (RefType == 2)
					doc.xref.compressedrefs.push_back(make_tuple<>(RefOfs,RefGen));

				jidx++;

				p += width;
				if (p >= destlen)
					break;
			}

			// And the trailer
			return S_OK;
		}

	};

}