#include"iostream"
#include"string"
#include"fstream"
#include"map"
#include"set"
#include"vector"
#include"algorithm"
#include"sys/stat.h"

class FileHandler
{
private:
	std::fstream stream;
public:
	FileHandler()
	{
		stream.exceptions(std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit | 
						  std::ofstream::failbit | std::ofstream::badbit | std::ofstream::eofbit);
	}
	void open(std::string fName, char* mod)
	{
		try
		{
			if(!strcmp(mod, "rd"))
			{
				stream.open(fName, std::ios::in | std::ios::binary);
				return;
			}
			if(!strcmp(mod, "wt"))
			{
				stream.open(fName, std::ios::out | std::ios::binary);
				return;
			}
			else
				std::cout << "Unknown mode, \'r\' & \'w\' are known\n";
		}
		catch(std::fstream::failure)
		{
			std::cout << "An error occurred during file opening" << std::endl;
		}
	}

	bool read(char * buf, unsigned int size)
	{
		try
		{
			if(stream.peek() != EOF)
			{
				if(stream.is_open())
				{
					stream.read(buf, size);
				}
				else
				{
					not_open();
				}
				return 1;
			}
		}
		catch(std::ifstream::failure fail)
		{
			if(!stream.fail())
			{
				return 0;
			}
			else
			{
				std::cout << "An error occurred during file reading: " << fail.what() << std::endl;
				return 0;
			}
		}
	}

	void write(char * buf, unsigned int size)
	{
		try
		{
			if(stream.is_open())
			{
				stream.write(buf, size);
			}
			else
			{
				not_open();
			}
		}
		catch(std::ofstream::failure fail)
		{
			std::cout << "An error occurred during file writing: " << fail.what() << std::endl;
		}
	}

	void seekg(int pos, std::ios_base::seekdir way)
	{
		try
		{
			stream.seekg(pos, way);
		}
		catch(std::ifstream::failure fail)
		{
			std::cout << "An error occurred during seek_g: " << fail.what() << std::endl;
		}
	}

	void close()
	{
		if(stream.is_open())
		{
			stream.close();
			return;
		}
		not_open();
	}

	int peek()
	{
		return stream.peek();
	}

	bool good()
	{
		if(!stream.good())
			return 0;
		return 1;
	}

	void not_open()
	{
		std::cout << "File wasnt open correctly\n";
	}

	~FileHandler(){}
};

void swap(char* str, int size)
{
	for(int i = 0; i < size / 2; ++i)
	{
		std::swap(str[i], str[size - i - 1]);
	}
}

void swap_frame(char *str, int h_size, std::string parts)
{
	int pos = 0, curr_part;
	for(int i = 0; i < parts.size(); ++i)
	{
		curr_part = parts[i] - '0';
		swap(str + pos, curr_part);
		pos += curr_part;
	}
}

void dummy(char*, int){}

void dummy_frame(char*, int, std::string){}

void term()
{
	std::cout << "Press Enter to exit...";
	std::cin.get();
	exit(-1);
}

union HexAccess
{
private:
	char charVal[4];
	unsigned int intVal;
public:
	HexAccess(){}

	void set_ch(char *c)
	{
		strncpy(charVal, c, 4);
	}

	int get_int()
	{
		return intVal;
	}

	char* get_ch()
	{
		return charVal;
	}
};

struct Format
{
	std::string type, format;
	char subtype;
	int size;

	Format(std::string a, std::string b, char c, int d):type(a), format(b), 
														subtype(c), size(d){}
};

struct FilesAndSize
{
	std::set<std::string> files;
	long long size;
	FilesAndSize(): size(0){}
};

typedef std::pair<unsigned int, std::auto_ptr<Format>> myPair;
typedef std::map<unsigned int, std::auto_ptr<Format>> myMap;

class MyException
{
public:
	MyException(std::string &s)
	{
		std::cout << "File " << s << " is not a pcap file in a supported format" << std::endl;
		term();
	}

	MyException(std::string &s, std::string t)
	{
		std::cout << "File " << s << " has " << t << " format, not compatable with the other files" << std::endl;
		term();
	}
};

class PcapMerger
{
private:
	myMap typesDict;
	myMap::iterator it;
	FilesAndSize filesByEnd[2];
	std::string outputFile, pcapFormat, headParts;
	std::auto_ptr<FileHandler> f, out;

	int gHeadSize, frHeadSize;
	void create_dictionary();
	void check_files(std::vector<std::string>&, int);
	void merge_files();
	void add_to_file(const std::string&, char, char, char);
public:
	PcapMerger(std::vector<std::string> &files, int quantity, std::string output): outputFile(output), gHeadSize(24)
	{
		f = std::auto_ptr<FileHandler>(new FileHandler());
		out = std::auto_ptr<FileHandler>(new FileHandler());
		create_dictionary();
		check_files(files, quantity);
		merge_files();
	}

	~PcapMerger(){}
};

void PcapMerger::create_dictionary()
{
	typesDict.insert(myPair (0xa1b2c3d4, new Format("default", "4444", 0, 16)));
	typesDict.insert(myPair (0xd4c3b2a1, new Format("default", "4444", 1, 16)));
	typesDict.insert(myPair (0xa1b23c4d, new Format("default ns", "4444", 0, 16)));
	typesDict.insert(myPair (0x4d3cb2a1, new Format("default ns", "4444", 1, 16)));
	typesDict.insert(myPair (0xa1b2cd34, new Format("Kuznetsov's", "4444421", 0, 23)));
	typesDict.insert(myPair (0x34cdb2a1, new Format("Kuznetsov's", "4444421", 1, 23)));
	typesDict.insert(myPair (0xa1e2cb12, new Format("netsniff-ng", "444422211", 0, 24)));
	typesDict.insert(myPair (0x12cbe2a1, new Format("netsniff-ng", "444422211", 1, 24)));
}

void PcapMerger::check_files(std::vector<std::string> &files, int quantity)
{
	HexAccess val;
	char buf[4];
	short mNumberLength = 4;
	struct stat fstatus;

	for(int i = 0; i < quantity; ++i)
	{
		try
		{
			f->open(files[i], "rd");
			f->read(buf, mNumberLength);
			swap(buf, 4);
			val.set_ch(buf);
			if(typesDict.count(val.get_int()) == 0)
				throw new MyException(files[i]);
			
			if(i == 0)
			{
				pcapFormat = typesDict[val.get_int()]->type;
				frHeadSize = typesDict[val.get_int()]->size;
				headParts = typesDict[val.get_int()]->format;
			}

			if(typesDict[val.get_int()]->type != pcapFormat)
				throw new MyException(files[i], typesDict[val.get_int()]->type);
			
			stat(files[i].c_str(), &fstatus);

			filesByEnd[typesDict[val.get_int()]->subtype].files.insert(files[i]);
			filesByEnd[typesDict[val.get_int()]->subtype].size += fstatus.st_size;
		}
		catch(MyException ex){}
		f->close();
	}
}

void PcapMerger::merge_files()
{
	char form = 0;
	form = filesByEnd[0].size < filesByEnd[1].size;

	std::set<std::string>::iterator it = filesByEnd[form].files.begin();
	try
	{
		out->open(outputFile, "wt");
		add_to_file(*it, 0, form, 0);
		++it;
		for(it; it != filesByEnd[form].files.end(); ++it)
		{
			add_to_file(*it, 1, form, 0);
		}
		for(it = filesByEnd[!form].files.begin(); it != filesByEnd[!form].files.end(); ++it)
		{
			add_to_file(*it, 1, !form, 1);
		}
	}
	catch(MyException ex){}
	out->close();
}

void PcapMerger::add_to_file(const std::string& from, char pos, char form, char sw)
{
	int packetSize = 0, count = 0, res = 1;
	char *headerBuf, *packBuf;
	HexAccess hack;
	void (*mod_pckt_sz)(char *, int);
	void (*mod_frm)(char *, int, std::string);

	mod_pckt_sz = (form == sw? swap: dummy);
	mod_frm = (sw == 0? dummy_frame: swap_frame);
	f->open(from, "rd");

	if(pos == 0)
	{
		headerBuf = new char[gHeadSize];
		f->read(headerBuf, gHeadSize);
		out->write(headerBuf, gHeadSize);
		delete[] headerBuf;
	}
	else
		f->seekg(gHeadSize, std::ios::beg);
	headerBuf = new char[frHeadSize];

	while(1)
	{
		res = f->read(headerBuf, frHeadSize);
		if(!res)
			break;
		mod_frm(headerBuf, frHeadSize, headParts);  
		out->write(headerBuf, frHeadSize);

		mod_pckt_sz(headerBuf + 8, 4);
		hack.set_ch(headerBuf + 8);
		packetSize = hack.get_int();
		packBuf = new char[packetSize];
		f->read(packBuf, packetSize);
		out->write(packBuf, packetSize);
		delete[] packBuf;
	}
	f->close();
	delete[] headerBuf;
}

int main(int argc, char* argv[])
{
	char headSet = 0, cnt = 0;
	std::vector<std::string> files;
	std::string tmp, out;
	for(int i = 1; i < argc; ++i)
	{
		if(strcmp(argv[i], "-o") == 0)
		{
			if(i == argc - 1)
			{
				std::cout << "Using default output file name \"merged.pcap\"";
				out = "merged.pcap";
				headSet = 1;
				break;
			}
			headSet = 1;
			out = argv[++i];
			continue;
		}
		tmp = argv[i];
		files.push_back(tmp);
		cnt++;
	}
	if(headSet == 0)
	{
		std::cout << "Using default output file name \"merged.pcap\"";
		out = "merged.pcap";
	}
	std::auto_ptr<PcapMerger> Mrg(new PcapMerger(files, cnt, out));
	return 0;
}
