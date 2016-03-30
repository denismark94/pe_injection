#include<fstream>
#include<Windows.h>
#include<iostream>

using namespace std;

DWORD num_of_sections;
DWORD address_of_entry_point;
DWORD image_base;
DWORD section_alignment;
DWORD file_alignment;
DWORD size_of_image;
DWORD import_dir_va;
DWORD import_dir_size;

int main(int argc, const char* argv[]) {
	cout<<argv[1]<<endl;
	ifstream pefile;
	pefile.open(argv[1], ios::in | ios::binary);
	if (!pefile.is_open())
	{
		cout << "Can't open file" << endl;
		return 0;
	}
	//calculating size of file
	pefile.seekg(0, ios::end);
	streamoff filesize = pefile.tellg();
	pefile.seekg(0);
	cout<<"Size: "<<filesize<<endl;
	//reach dos_header
	IMAGE_DOS_HEADER dos_header;
	pefile.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
	cout<<hex<<showbase<<"Magic: "<<dos_header.e_magic<<endl;
	pefile.seekg(dos_header.e_lfanew);

	DWORD pe_signature;
	pefile.read(reinterpret_cast<char*>(&pe_signature), sizeof(DWORD));
	cout<<"PE Signature: "<<pe_signature<<endl;

	IMAGE_FILE_HEADER file_header;
	pefile.read(reinterpret_cast<char*>(&file_header), sizeof(IMAGE_FILE_HEADER));
	cout<<"Machine: "<<file_header.Machine<<endl;
	num_of_sections = file_header.NumberOfSections;
	cout<<"Number of sections:"<<num_of_sections<<endl;

	IMAGE_OPTIONAL_HEADER optional_header;
	pefile.read(reinterpret_cast<char*>(&optional_header), sizeof(IMAGE_OPTIONAL_HEADER));

	address_of_entry_point = optional_header.AddressOfEntryPoint;
	cout<<"Address of entry point: "<<address_of_entry_point<<endl;

	image_base = optional_header.ImageBase;
	cout<<"Image base: "<<image_base<<endl;

	section_alignment = optional_header.SectionAlignment;
	cout<<"Section alignment: "<<section_alignment<<endl;

	file_alignment = optional_header.FileAlignment;
	cout<<"File alignment: "<<file_alignment<<endl;

	size_of_image = optional_header.SizeOfImage;
	cout<<"Size of image: "<<size_of_image<<endl;

	import_dir_va = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	cout<<"Virtual address of import directory: "<<import_dir_va<<endl;

	import_dir_size = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	cout<<"Size of import directory: "<<import_dir_size<<endl;
}