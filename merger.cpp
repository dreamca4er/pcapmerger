#include"filehandler.h"
#include"merger.h"

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

MyException::MyException(std::string &s)
{
	std::cout << "File " << s << " is not a pcap file in a supported format" << std::endl;
	term();
}

MyException::MyException(std::string &s, std::string t)
{
	std::cout << "File " << s << " has " << t << " format, not compatable with the other files" << std::endl;
	term();
}

PcapMerger::PcapMerger(std::vector<std::string> &files, int quantity, std::string output)
{
	outputFile = output;
	gHeadSize = 24;
	f = std::auto_ptr<FileHandler>(new FileHandler());
	out = std::auto_ptr<FileHandler>(new FileHandler());
	create_dictionary();
	check_files(files, quantity);
	merge_files();
}

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
			add_to_file(*it, 1, form, 0);
		
		for(it = filesByEnd[!form].files.begin(); it != filesByEnd[!form].files.end(); ++it)
			add_to_file(*it, 1, !form, 1);
	}
	catch(MyException ex){}
	out->close();
}

void PcapMerger::add_to_file(const std::string& from, char pos, char form, char sw)
{
	int packetSize = 0, count = 0;
	char *headerBuf, *packBuf, res = 1;
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
	while(f->good())
	{
		res = f->read(headerBuf, frHeadSize);
		if(!res)
			break;
		mod_frm(headerBuf, frHeadSize, headParts);  
		out->write(headerBuf, frHeadSize);

		mod_pckt_sz(headerBuf + 8, 4);
		hack.set_ch(headerBuf + 8);
		packetSize = hack.get_int();

		if(f->data_q(packetSize) > 0)
			packetSize -= f->data_q(packetSize);

		packBuf = new char[packetSize];
		f->read(packBuf, packetSize);
		out->write(packBuf, packetSize);
		delete[] packBuf;
	}
	f->close();
	delete[] headerBuf;
}