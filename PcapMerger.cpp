#include"iostream"
#include"string"
#include"fstream"
#include"map"
#include"set"
#include"vector"
#include"algorithm"
#include<sys/stat.h>
#include"sstream"

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
	MyException(char *s)
	{
		std::cout << "File " << s << " is not a pcap file in a supported format" << std::endl;
		term();
	}

	MyException(char *s, std::string t)
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
	std::ofstream out;
	std::ifstream f;

	int gHeadSize, frHeadSize;
	void create_dictionary();
	void check_files(char**, int);
	void merge_files();
	void add_to_file(const std::string&, char, char, char);
public:
	PcapMerger(char** files, int quantity, char* output): outputFile(output), gHeadSize(24)
	{
		out.exceptions(std::ofstream::failbit | std::ofstream::badbit | std::ofstream::eofbit);
		f.exceptions(std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit);
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

void PcapMerger::check_files(char** files, int quantity)
{
	HexAccess val;
	char buf[4];
	short mNumberLength = 4;
	struct stat fstatus;
	for(int i = 1; i <= quantity; ++i)
	{
		try
		{
			f.open(files[i], std::ios::binary);
			f.read(buf, mNumberLength);
			swap(buf, 4);
			val.set_ch(buf);
			if(typesDict.count(val.get_int()) == 0)
				throw new MyException(files[i]);
			
			if(i == 1)
			{
				pcapFormat = typesDict[val.get_int()]->type;
				frHeadSize = typesDict[val.get_int()]->size;
				headParts = typesDict[val.get_int()]->format;
			}

			if(typesDict[val.get_int()]->type != pcapFormat)
				throw new MyException(files[i], typesDict[val.get_int()]->type);
			
			stat(files[i], &fstatus);

			filesByEnd[typesDict[val.get_int()]->subtype].files.insert(files[i]);
			filesByEnd[typesDict[val.get_int()]->subtype].size += fstatus.st_size;
		}
		catch(std::ifstream::failure fail)
		{
			std::cout << "An error occurred during file opening/reading: " << fail.what() << std::endl;
			term();
		}
		catch(MyException ex){}
		f.close();
	}
}

void PcapMerger::merge_files()
{
	char form = 0;
	form = filesByEnd[0].size < filesByEnd[1].size;

	std::set<std::string>::iterator it = filesByEnd[form].files.begin();
	try
	{
		out.open(outputFile, std::ios::binary);
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
	catch(std::ifstream::failure fail)
	{
		std::cout << "An error occurred during working with file: " << fail.what() << std::endl;
		term();
	}
	catch(MyException ex){}
	out.close();
}

void PcapMerger::add_to_file(const std::string& from, char pos, char form, char sw)
{
	int packetSize = 0, count = 0;
	char *headerBuf, *packBuf;
	HexAccess hack;
	void (*mod_pckt_sz)(char *, int);
	void (*mod_frm)(char *, int, std::string);

	mod_pckt_sz = (form == sw? swap: dummy);
	mod_frm = (sw == 0? dummy_frame: swap_frame);
	f.open(from, std::ios::binary);

	if(pos == 0)
	{
		headerBuf = new char[gHeadSize];
		f.read(headerBuf, gHeadSize);
		out.write(headerBuf, gHeadSize);
		delete[] headerBuf;
	}
	else
		f.seekg(gHeadSize, std::ios::beg);
	headerBuf = new char[frHeadSize];

	while(1)
	{
		try
		{
			f.read(headerBuf, frHeadSize);
			mod_frm(headerBuf, frHeadSize, headParts);  
			out.write(headerBuf, frHeadSize);

			mod_pckt_sz(headerBuf + 8, 4);
			hack.set_ch(headerBuf + 8);
			packetSize = hack.get_int();
			packBuf = new char[packetSize];
			f.read(packBuf, packetSize);
			out.write(packBuf, packetSize);
			delete[] packBuf;
		}
		catch(std::ifstream::failure fail)
		{
			break;
		}
	}
	f.close();
	delete[] headerBuf;
}

int main(int argc, char* argv[])
{
	char* out = "merged.cap";
	std::auto_ptr<PcapMerger> Mrg(new PcapMerger(argv, argc - 1, out));
	return 0;
}