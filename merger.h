#ifndef MERGER_H
#define MERGER_H

#include"iostream"
#include"vector"
#include"set"
#include"map"
#include"string"
#include"fstream"
#include"sys/stat.h"

void term();
void swap(char* str, int size);

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

struct Format
{
	std::string type, format;
	char subtype;
	int size;
	Format(std::string a, std::string b, char c, int d):type(a), format(b), subtype(c), size(d){}
};

typedef std::pair<unsigned int, std::auto_ptr<Format>> myPair;
typedef std::map<unsigned int, std::auto_ptr<Format>> myMap;

union HexAccess
{
private:
	char charVal[4];
	unsigned int intVal;
public:
	HexAccess(){}

	void set_ch(char *c){strncpy(charVal, c, 4);}

	int get_int(){return intVal;}

	char* get_ch(){return charVal;}
};

struct FilesAndSize
{
	std::set<std::string> files;
	long long size;
	FilesAndSize(): size(0){}
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
	PcapMerger(std::vector<std::string>&, int, std::string);
	~PcapMerger(){}
};

#endif MERGER_H