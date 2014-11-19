#include"iostream"
#include"string"
#include"vector"
#include"filehandler.h"
#include"merger.h"

int main(int argc, char* argv[])
{
	char headSet = 0, cnt = 0;
	std::vector<std::string> files;
	std::string tmp, out;
	if(argc == 1)
	{
		std::cout << "Usage: file_1 [[file_2]...[file_n]] -o output_file\n";
		exit(-1);
	}
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
