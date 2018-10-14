


#ifdef _WIN64
#include ".\\packages\\zlib-msvc14-x86.1.2.11.7795\\build\\native\\include\\zlib.h"
#else
#include ".\\packages\\zlib-vc140-static-64.1.2.11\\lib\\native\\include\\zlib.h"
#endif



namespace PDF
{

#ifdef _WIN64
	typedef signed long long ssize_t;
#else
	typedef signed long ssize_t;
#endif

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

	inline ssize_t memstr(const char* arr, size_t length, const char* tofind, size_t flength) {
		for (size_t i = 0; i < length - flength; ++i) {
			if (memcmp(arr + i, tofind, flength) == 0)
				return i;
		}
		return (ssize_t)-1;
	}

	inline ssize_t memrstr(const char* arr, size_t length, const char* tofind, size_t flength) {
		for (ssize_t i = (length - flength); i >= 0; --i) {
			if (memcmp(arr + i, tofind, flength) == 0)
				return i;
		}
		return (ssize_t)-1;
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

	inline string BinToHex(const unsigned char* d, size_t sz)
	{
		string a;
		char f[30] = { 0 };
		for (auto i = 0; i < sz; i++)
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

		for (auto i = 0; i < hex.length(); i += 2)
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


		bool Parse(unsigned long long nu,const char *d,bool NoUp = false)
		{
			auto orgd = d;
			INX* n = &content;
			num = nu;
			unsigned long long i = 0;
			if (nu == (unsigned long long)-1)
			{
				nu = atoi(d);
				num = nu;
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
			return true;
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



		HRESULT XParse(const class DOC&,const char *d,OBJECT& trl)
		{
			unsigned long long i = 0;
			string xrtag = upoline(d, i);
			if (xrtag != "xref")
				return E_UNEXPECTED;
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
						trl.Parse(0, d);
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
							return false;

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


		OBJECT* findobject(size_t num)
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

		INX* findname(INX*d,string Name, size_t* iIdx = 0, bool R = false)
		{
			if (!d)
				return 0;
			if (d->Type == INXTYPE::TYPE_DIC)
			{
				size_t ii = 0;
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
			size_t jj = 0;
			for (auto& cc : d->Contents)
			{
				auto ifo = findname(&cc, Name, iIdx, R);
				if (ifo)
					return ifo;
				jj++;
			}
			return 0;

		}

		ssize_t root()
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

		ssize_t size()
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

		ssize_t info()
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


		ssize_t root()
		{
			if (docs.empty())
				return -1;
			auto& last = docs[0];
			return last.root();
		}

		ssize_t info()
		{
			if (docs.empty())
				return -1;
			auto& last = docs[0];
			return last.info();
		}


		OBJECT* findobject(size_t num)
		{
			for (auto& doc : docs)
			{
				OBJECT* dd = doc.findobject(num);
				if (dd)
					return dd;
			}
			return 0;
		}

		INX* findname(INX* dd, string Name, size_t* iIdx = 0,bool R = false)
		{
			if (!dd)
				return 0;
			if (dd->Type == INXTYPE::TYPE_DIC)
			{
				size_t ii = 0;
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


		INX* findname(OBJECT* dd, string Name,size_t* iIdx = 0,bool R = false)
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
		bool Parse2(const char* dd, unsigned long long s)
		{
			if (!dd)
				return false;
			d = dd;
			sz = s;
			const char* ss = dd;
			if (strncmp(ss, "%PDF-", 5) != 0)
				return false;
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
					return false;

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
				}

				if (hrxref != S_OK)
					return false;

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
					if (XrefAsObject)
						num = (unsigned long long)-1;
					o.p = get<1>(s2);
					o.Parse(num, dd + get<1>(s2));
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
						o.Parse(np.first, unp + np.second, true);
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
				auto npr = findname(&doc.xref.if_object, "Prev");
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
				return false;

			return true;
		}

		HRESULT ParseXrefAsObject(DOC& doc, const char *d, OBJECT& trl)
		{
			UNREFERENCED_PARAMETER(trl);
			OBJECT& o = doc.xref.if_object;
			if (!o.Parse(0, d))
				return E_FAIL;


			if (o.str_size == 0)
				return E_FAIL;

			// Decompress Stream
			vector<char> uncs(1048576);
			unsigned long destlen = (uLong)uncs.size();
			auto ures  = uncompress((Bytef*)uncs.data(), &destlen,(Bytef*) d + o.str_pos, (uLong)o.str_size);
			if (ures != 0)
				return E_FAIL;

			// Type PNG support
			auto prd = doc.findname(&o.content, "Predictor",0,true);
			if (!prd)
				return E_FAIL;

			int Val = atoi(prd->Value.c_str());
			if (Val < 10)
				return E_FAIL;

			// Widths
			auto cw = doc.findname(&o.content, "W", 0, true);
			if (!cw)
				return E_FAIL;
			if (cw->Contents.size() == 0)
				return E_FAIL;
			if (cw->Contents.front().Type != INXTYPE::TYPE_ARRAY)
				return E_FAIL;

			auto widths = cw->Contents.front().Value;
			auto r = split(widths.c_str(), ' ');
			if (r.size() != 3)
				return E_FAIL;

			// Support [1,X,1] currently up to [1,8,1]
			if (atoi(r[0].c_str()) != 1)
				return E_FAIL;
			if (atoi(r[1].c_str()) > 8)
				return E_FAIL;
			if (atoi(r[2].c_str()) != 1)
				return E_FAIL;


			int width = 0;
			for (auto& rr : r)
			{
				width += atoi(rr.c_str());
			}

			// Strip last 10, is CRC
			destlen -= 10;

			// Loop rows (width value = width + 1)
			vector<unsigned char> PrevRow(width);
			
			unsigned long long jidx = 0;

			for (size_t p = 0 ; ;)
			{
				const char* dd = uncs.data() + p;

				// Strip first \x02.
				p++;
				dd++;

				long long RefType = 0;
				unsigned long long RefOfs = 0;
				long long RefGen = 0;
				int eb = 0;

				for (int row = 0; row < width ; row++)
				{
					unsigned char by = dd[row];
					by += PrevRow[row];
					PrevRow[row] = by;


					if (row == 0)
					{
						eb = 8* ( atoi(r[1].c_str()) - 1);
						RefType = by;
						RefOfs = 0;
					}
					if (row >= 1 && row < (width - 1))
					{
						unsigned long long s2 = by;
						unsigned long long r = eb;
						RefOfs |= (s2 << r);
						eb -= 8;
					}
					if (row == (width - 1))
					{
						RefGen = by;
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


/*
		HRESULT PrepareSigning(AdES::LEVEL levx,vector<char>& to_sign, vector<char>& res)
		{

			// We have parsed it...
			// Find Contents
			if (docs.empty())
				return E_UNEXPECTED;

			auto lastroot = root();
			if (lastroot == -1)
				return E_UNEXPECTED;
			auto rootobject = findobject(lastroot);
			if (!rootobject)
				return E_UNEXPECTED;
			auto lastpages = findname(rootobject,"Pages");
			if (lastpages == 0)
				return E_UNEXPECTED;
			auto iiPage = atoll(lastpages->Value.c_str());
			auto PageObject = findobject(iiPage);
			if (!PageObject)
				return E_UNEXPECTED;
			auto lastkids = findname(PageObject, "Kids");
			if (lastkids == 0)
				return E_UNEXPECTED;
			string firstref = "";
			if (lastkids->Contents.size() >= 1 && lastkids->Contents.front().Type == INXTYPE::TYPE_ARRAY)
			{
				auto spl = split(lastkids->Contents.front().Value, ' ');
				while(!spl.empty())
				{
					if (spl[0] == "")
					{
						spl.erase(spl.begin());
						continue;
					}
					firstref = spl[0];
					break;
				}
			}
			else
			{
				auto spl = split(lastkids->Value, ' ');
				while (!spl.empty())
				{
					if (spl[0] == "")
					{
						spl.erase(spl.begin());
						continue;
					}
					firstref = spl[0];
					break;
				}
			}

			int iFirstRef = atoll(firstref.c_str());
			if (iFirstRef == 0)
				return E_UNEXPECTED;
			auto RefObject = findobject(iFirstRef);
			if (!RefObject)
				return E_UNEXPECTED;

			// Serialization of this reference
			if (RefObject->content.Type != INXTYPE::TYPE_DIC)
				return E_UNEXPECTED;

			auto lastcnt = findname(RefObject, "Contents");
			if (lastcnt == 0)
				return E_UNEXPECTED;

			auto& last = docs[0];
			auto mxd = mmax() + 1;
			int iContents = atoll(lastcnt->Value.c_str());


			bool InRL = false;
			char* ps = to_sign.data();
			char* ps2 = res.data();
			to_sign.resize(sz);
			memcpy(to_sign.data(), d, sz);
			res.resize(sz);
			memcpy(res.data(), d, sz);

//			int iRoot = mxd + 1;
//			int iPages = mxd + 2;
//			int iPage = mxd + 3;
//			int iSignature = mxd + 6;
//			int iXOBject = mxd + 7;
//			int iDescribeSignature = mxd + 8;
//			int iFont = mxd + 9;
//			int iFont2 = mxd + 10;
//			int iProducer = mxd + 11;


			int iRoot = mxd + 1;
			int iPages = mxd + 2;
			int iPage = mxd + 3;
			int iSignature = mxd + 4;
			int iXOBject = mxd + 5;
			int iDescribeSignature = mxd + 6;
			int iFont = mxd + 7;
			int iFont2 = mxd + 8;
			int iProducer = mxd + 9;


			INX annots;
			annots.Type = INXTYPE::TYPE_NAME;
			annots.Name = "Annots";
			INX annotsr;
			annotsr.Type = INXTYPE::TYPE_ARRAY;
			astring annot_string;
			annot_string.Format("%u 0 R", iDescribeSignature);
			annotsr.Value = annot_string;
			annots.Contents.push_back(annotsr);
			RefObject->content.Contents.push_front(annots);
			vector<char> strref;
			auto refp = findname(RefObject, "Parent");
			// iPages in Parent
			refp->Value.Format("%u 0 R", iPages);
			RefObject->content.Serialize(strref);
			strref.resize(strref.size() + 1);

			map<int, unsigned long long> xrefs;

			AddCh(to_sign, string("\n"));
			AddCh(res, string("\n"));
			astring vSignatureDescriptor;
			vSignatureDescriptor.Format("%u 0 obj\n<</F 132/Type/Annot/Subtype/Widget/Rect[0 0 0 0]/FT/Sig/DR<<>>/T(Signature1)/V %u 0 R/P %u 0 R/AP<</N %u 0 R>>>>\nendobj\n",iDescribeSignature,iSignature,iPage,iXOBject);
			xrefs[iDescribeSignature] = to_sign.size();
			AddCh(to_sign, vSignatureDescriptor);
			AddCh(res, vSignatureDescriptor);

			astring vSignature;
			if (InRL)
				vSignature.Format("%u 0 obj\n<</Contents <", iSignature);
			else
				vSignature.Format("%u 0 obj\n<</Contents ", iSignature);
			xrefs[iSignature] = to_sign.size();
			AddCh(to_sign, vSignature);
			AddCh(res, vSignature);

			auto u1 = to_sign.size();

			string vs;
			int de = 30000;
			if (!InRL)
				vs += "<";
			for (int i = 0; i < de; i++)
				vs += "00";
			auto ures = res.size();
			if (!InRL)
				vs += ">";
			AddCh(res, vs);


			string de3 = "adbe.pkcs7.detached";
			if (levx != AdES::LEVEL::CMS)
				de3 = "ETSI.CAdES.detached";
			astring dd;
			SYSTEMTIME sT;
			GetSystemTime(&sT);
			dd.Format("%04u%02u%02u%02u%02u%02u+00'00'", sT.wYear, sT.wMonth, sT.wDay, sT.wHour, sT.wMinute, sT.wSecond);
			
			string vafter;

			astring vSignatureAfter;
			astring vRoot;
			astring vFont;
			astring vFont2;
			astring v7, v7b;
			astring vProducer;
			astring vPage;
			astring vPages;
			astring vend;
			astring xrf;
			astring trl;
			astring sxref;
			vend += "%%EOF\x0a";

			if (!InRL)
				vSignatureAfter.Format("/Type/Sig/SubFilter/%s/M(D:%s)/ByteRange [0 %u %u %03u]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), dd.c_str(), u1, u1 + vs.length(), 0);
			else
				vSignatureAfter.Format(">/Type/Sig/SubFilter/%s/M(D:%s)/ByteRange [0 %u %u %03u]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), dd.c_str(), u1, u1 + vs.length(), 0);
			vafter += vSignatureAfter;
			vFont.Format("%u 0 obj\n<</BaseFont/Helvetica/Type/Font/Subtype/Type1/Encoding/WinAnsiEncoding/Name/Helv>>\nendobj\n",iFont);
			xrefs[iFont] = vafter.size() + res.size() + 1;
			vafter += vFont;
			vFont2.Format("%u 0 obj\n<</BaseFont/ZapfDingbats/Type/Font/Subtype/Type1/Name/ZaDb>>\nendobj\n",iFont2);
			xrefs[iFont2] = vafter.size() + res.size() + 1;
			vafter += vFont2;
			v7.Format("%u 0 obj\n<</Type/XObject/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>>/Subtype/Form/BBox[0 0 0 0]/Matrix [1 0 0 1 0 0]/Length 8/FormType 1/Filter/FlateDecode>>stream\x0a\x78\x9c\x03",iXOBject); 			v7b.Format("\x01\x0d");			v7b += "endstream\nendobj\n";
			xrefs[iXOBject] = vafter.size() + res.size() + 1;
			vafter += v7;			vafter.resize(vafter.size() + 4);			vafter += v7b;
//			vPage.Format("%u 0 obj\n<</Parent %u 0 R/Contents %u 0 R/Type/Page/Resources<</Font<</Helv %u 0 R>>>>/Annots[%u 0 R]>>\nendobj\n", iPage, iPages, iContents, iFont, iDescribeSignature);
			vPage.Format("%u 0 obj\n%s\r\nendobj\r\n", iPage,strref.data());
			xrefs[iPage] = vafter.size() + res.size() + 1;
			vafter += vPage;
			vPages.Format("%u 0 obj\n<</Type/Pages/MediaBox[0 0 200 200]/Count 1/Kids[%u 0 R]>>\nendobj\n",iPages,iPage);
			xrefs[iPages] = vafter.size() + res.size() + 1;
			vafter += vPages;
			vRoot.Format("%u 0 obj\n<</Type/Catalog/AcroForm<</Fields[%u 0 R]/DR<</Font<</Helv %u 0 R/ZaDb %u 0 R>>>>/DA(/Helv 0 Tf 0 g )/SigFlags 3>>/Pages %u 0 R>>\nendobj\n", iRoot, iDescribeSignature, iFont,iFont2,iPages);
			xrefs[iRoot] = vafter.size() + res.size() + 1;
			vafter += vRoot;
			vProducer.Format("%u 0 obj\n<</Producer(AdES Tools)/ModDate(D:20181002132630+03'00')>>\nendobj\n",iProducer);
			xrefs[iProducer] = vafter.size() + res.size() + 1;
			vafter += vProducer;
			// build xref
			unsigned long long xrefpos = vafter.size() + res.size() + 1;

			// Build xrefs
			vector<int> xrint = { iRoot ,iPages, iPage, iSignature, iXOBject, iDescribeSignature, iFont, iFont2, iProducer };
			xrf.Format("xref\n%u 9\n", iRoot);
			for (auto s : xrint)
			{
				astring xg;
				auto j = xrefs[s];
				if (j != 0)
					xg.Format("%010llu 00000 n \n", j);
				else
					xg.Format("%010llu 00000 f \n", 0LL);
				xrf += xg;

			}


			vafter += xrf;
			trl.Format("trailer\n<</Root %u 0 R/Prev %llu/Info %u 0 R/Size 12>>\n", iRoot, last.xref.p,iProducer);
			vafter += trl;
			sxref.Format("startxref\n%llu\n", xrefpos);
			vafter += sxref;
			vafter += vend;

			size_t u2 = vafter.length();
			vafter = "";

			if (!InRL)
				vSignatureAfter.Format("/Type/Sig/SubFilter/%s/M(D:%s)/ByteRange [0 %u %u %03u]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), dd.c_str(), u1, u1 + vs.length(), u2 + 1);
			else
				vSignatureAfter.Format(">/Type/Sig/SubFilter/%s/M(D:%s)/ByteRange [0 %u %u %03u]/Filter/Adobe.PPKLite>>\nendobj\n", de3.c_str(), dd.c_str(), u1, u1 + vs.length(), u2 + 1);
			vafter += vSignatureAfter;
			vafter += vFont;
			vafter += vFont2;
			vafter += v7;			vafter.resize(vafter.size() + 4);			vafter += v7b;
			vafter += vPage;
			vafter += vPages;
			vafter += vRoot;
			vafter += vProducer;
			vafter += xrf;
			vafter += trl;
			vafter += sxref;
			vafter += vend;

			AddCh(to_sign, vafter);
			AddCh(res, vafter);

			ps = to_sign.data();
			ps2 = res.data();


			// Sign
			AdES ad;
			auto cc = HrGetSigner(L"ch.michael@cyta.gr");
			vector<AdES::CERT> ce;
			putin(cc, ce);
			//auto cc2 = HrGetSigner(L"m.chourdakis@music.uoa.gr");
			//putin(cc2, ce);
			AdES::SIGNPARAMETERS p;
			vector<char> r;
			p.Attached = AdES::ATTACHTYPE::DETACHED;
			p.PAdES = true;
			auto hrx = ad.Sign(levx, to_sign.data(), to_sign.size(), ce, p, r);
			if (FAILED(hrx))
				return hrx;
//			AdES::LEVEL lev;
//			vector<char> org;
//			ad.Verify(r.data(), r.size(), lev, 0, 0, &org);
//			char* a2 = (char*)org.data();

 			char* pv = res.data() + ures;
			if (!InRL)
				pv++;
			for (int i = 0; i < de; i++)
			{
				if (i >= r.size())
					break;

				unsigned char x = (unsigned char)r[i];
				char g[13];
				sprintf_s(g, 13, "%02X", x);
				memcpy(pv, g, 2);
				pv += 2;
			}


			return S_OK;
		}
*/

	};

}