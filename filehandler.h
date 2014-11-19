#ifndef FILEHANDLER_H
#define FILEHANDLER_H

#include"iostream"
#include"string"
#include"fstream"

class FileHandler
{
private:
	std::fstream stream;
	std::string name;
public:
	FileHandler();

	void open(std::string fName, char* mod);

	bool read(char * buf, unsigned int size);

	void write(char * buf, unsigned int size);

	void seekg(int pos, std::ios_base::seekdir way);

	int data_q(int to_read);

	void close();

	int length();

	int peek();
	
	bool good();
	
	void not_open();

	~FileHandler(){}
};

#endif FILEHANDLER.H