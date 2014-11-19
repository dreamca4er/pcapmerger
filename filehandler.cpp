#include"filehandler.h"

FileHandler::FileHandler()
{
	stream.exceptions(std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit | 
						std::ofstream::failbit | std::ofstream::badbit | std::ofstream::eofbit);
}

void FileHandler::open(std::string fName, char* mod)
{
	try
	{
		name = fName;
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
		std::cout << "An error occurred during opening " << name << std::endl;
		std::cout << "Press Enter to exit...";
		std::cin.get();
		exit(-1);
	}
}

bool FileHandler::read(char * buf, unsigned int size)
{
	try
	{
		if(stream.peek() != EOF)
		{
			if(stream.is_open())
				stream.read(buf, size);
			else
				not_open();
			return 1;
		}
	}
	catch(std::ifstream::failure fail)
	{
		if(!stream.fail())
			return 0;
		else
		{
			std::cout << "File " << name << " ended abruptly, possible loss of data\n";
			return 0;
		}
	}
}

void FileHandler::write(char * buf, unsigned int size)
{
	try
	{
		if(stream.is_open())
			stream.write(buf, size);
		else
			not_open();
	}
	catch(std::ofstream::failure fail)
	{
		std::cout << "An error occurred during file writing: " << fail.what() << std::endl;
	}
}

void FileHandler::seekg(int pos, std::ios_base::seekdir way)
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

int FileHandler::data_q(int to_read)
{
	return (int)stream.tellg() + to_read - length();
}

void FileHandler::close()
{
	if(stream.is_open())
	{
		stream.close();
		return;
	}
	not_open();
}

int FileHandler::length()
{
	int pos = stream.tellg(), length;
	stream.seekg (0, stream.end);
	length = stream.tellg();
	stream.seekg (pos, stream.beg);
	return length;
}

int FileHandler::peek()
{
	return stream.peek();
}

bool FileHandler::good()
{
	return stream.good();
}

void FileHandler::not_open()
{
	std::cout << "File wasnt open correctly\n";
}
