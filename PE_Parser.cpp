#include "Windows.h"
#include <iostream>
#include <string>
using namespace std;

void printDOSHeader(PIMAGE_DOS_HEADER dosHeader);
void printNTSignature(PIMAGE_NT_HEADERS64 imageNTHeaders);
void printFileHeader(PIMAGE_NT_HEADERS64 imageNTHeaders);
void printOptionalHeader(PIMAGE_NT_HEADERS64 imageNTHeaders);
void printSectionHeader(PIMAGE_SECTION_HEADER imageSectionHeader, DWORD numberOfSections);
void printIAT(PIMAGE_SECTION_HEADER imageSectionHeader, DWORD numberOfSections, IMAGE_DATA_DIRECTORY importTable, DWORD fileBuffer);
int main(int argc, char* argv[]) {
	string fileName;
	printf("Enter file name: ");
	getline(cin, fileName);

	HANDLE file = CreateFileA(
		fileName.c_str(),
		GENERIC_ALL,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (file == INVALID_HANDLE_VALUE) {
		printf("Can't open file");
		return -1;
	}

	DWORD fileSize = GetFileSize(file, NULL);

	LPVOID fileBuffer = HeapAlloc(GetProcessHeap(), 0, fileSize);
	if (fileBuffer == NULL) {
		printf("Can't alloc\n");
		CloseHandle(file);
		return -1;
	}
	DWORD bytesRead = 0;
	if (ReadFile(file, fileBuffer, fileSize, &bytesRead, NULL) == FALSE) {
		printf("Can't read file");
		HeapFree(GetProcessHeap(), 1, fileBuffer);
		CloseHandle(file);
		return -1;
	}

	//IMAGE_DOS_HEADER
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	printDOSHeader(dosHeader);

	// PE signature
	PIMAGE_NT_HEADERS64 imageNTHeaders = (PIMAGE_NT_HEADERS64)((DWORD)fileBuffer + dosHeader->e_lfanew);
	printNTSignature(imageNTHeaders);
	//FILE_HEADER
	printFileHeader(imageNTHeaders);

	//OPTIONAL_HEADER
	printOptionalHeader(imageNTHeaders);

	PIMAGE_SECTION_HEADER imageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)fileBuffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	printSectionHeader(imageSectionHeader, imageNTHeaders->FileHeader.NumberOfSections);

	printIAT(imageSectionHeader, imageNTHeaders->FileHeader.NumberOfSections, imageNTHeaders->OptionalHeader.DataDirectory[1], (DWORD)fileBuffer);
	HeapFree(GetProcessHeap(), 1, fileBuffer);
	CloseHandle(file);
	return 0;
}


void printDOSHeader(PIMAGE_DOS_HEADER dosHeader) {
	printf("******* IMAGE DOS HEADER *******\n");
	printf("\t\t%x\t\tMagic Number\n", dosHeader->e_magic);
	printf("\t\t%x\t\tBytes on last page of file\n", dosHeader->e_cblp);
	printf("\t\t%x\t\tPages in file\n", dosHeader->e_cp);
	printf("\t\t%x\t\tRelocations\n", dosHeader->e_crlc);
	printf("\t\t%x\t\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
	printf("\t\t%x\t\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("\t\t%x\t\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("\t\t%x\t\tInitial (relative) SS value\n", dosHeader->e_ss);
	printf("\t\t%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t\t%x\t\tChecksum\n", dosHeader->e_csum);
	printf("\t\t%x\t\tInitial IP value\n", dosHeader->e_ip);
	printf("\t\t%x\t\tInitial (relative) CS value\n", dosHeader->e_cs);
	printf("\t\t%x\t\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("\t\t%x\t\tOverlay number\n", dosHeader->e_ovno);
	printf("\t\t%x\t\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
	printf("\t\t%x\t\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
	printf("\t\t%x\t\tFile address of new exe header\n", dosHeader->e_lfanew);
}

void printNTSignature(PIMAGE_NT_HEADERS64 imageNTHeaders) {
	printf("\n******* NT HEADER *******\n");
	if (imageNTHeaders->Signature == IMAGE_DOS_SIGNATURE) {
		printf("\t\tMZ\t\tSignature\n");
	}
	else if (imageNTHeaders->Signature == IMAGE_OS2_SIGNATURE) {
		printf("\t\tNE\t\tSignature\n");
	}
	else if (imageNTHeaders->Signature == IMAGE_OS2_SIGNATURE_LE) {
		printf("\t\tLE\t\tSignature\n");
	}
	else if (imageNTHeaders->Signature == IMAGE_NT_SIGNATURE) {
		printf("\t\tPE00\t\tSignature\n");
	}
	else {
		printf("\t\tUNKNOWN\t\tSignature\n");
	}
}

void printFileHeader(PIMAGE_NT_HEADERS64 imageNTHeaders) {
	printf("\n******* FILE HEADER *******\n");
	const char* machine;
	switch (imageNTHeaders->FileHeader.Machine) {
	case IMAGE_FILE_MACHINE_UNKNOWN:
		machine = "Unknown";
		break;
	case IMAGE_FILE_MACHINE_AM33:
		machine = "Matsushita AM33";
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		machine = "x64";
		break;
	case IMAGE_FILE_MACHINE_ARM:
		machine = "ARM LE";
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		machine = "ARM64 LE";
		break;
	case IMAGE_FILE_MACHINE_ARMNT:
		machine = "ARM Thumb-2 LE";
		break;
	case IMAGE_FILE_MACHINE_EBC:
		machine = "EFI byte code";
		break;
	case IMAGE_FILE_MACHINE_I386:
		machine = "Intel 386";
		break;
	case IMAGE_FILE_MACHINE_IA64:
		machine = "Intel Itanium";
		break;
	case IMAGE_FILE_MACHINE_M32R:
		machine = "Mitsubishi M32R";
		break;
	case IMAGE_FILE_MACHINE_MIPS16:
		machine = "MIPS16";
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		machine = "MIPS with FPU";
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU16:
		machine = "MIPS16 with FPU";
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		machine = "Power PC";
		break;
	case IMAGE_FILE_MACHINE_POWERPCFP:
		machine = "Power PC with floating point";
		break;
	case IMAGE_FILE_MACHINE_R4000:
		machine = "MIPS";
		break;
	case 0x5032:
		machine = "RISC-V 32-bit";
		break;
	case 0x5064:
		machine = "RISC-V 64-bit";
		break;
	case 0x5128:
		machine = "RISC-V 128-bit";
		break;
	case IMAGE_FILE_MACHINE_SH3:
		machine = "Hitachi SH3";
		break;
	case IMAGE_FILE_MACHINE_SH3DSP:
		machine = "Hitachi SH3 DSP";
		break;
	case IMAGE_FILE_MACHINE_SH4:
		machine = "Hitachi SH4P";
		break;
	case IMAGE_FILE_MACHINE_SH5:
		machine = "Hitachi SH5";
		break;
	case IMAGE_FILE_MACHINE_THUMB:
		machine = "Thumb";
		break;
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		machine = "MIPS WCE v2";
		break;
	default:
		machine = "UNKNOWN";
	}

	const char* characteristics;
	switch (imageNTHeaders->FileHeader.Characteristics) {
	case IMAGE_FILE_RELOCS_STRIPPED:
		characteristics = "IMAGE_FILE_RELOCS_STRIPPED";
		break;
	case IMAGE_FILE_EXECUTABLE_IMAGE:
		characteristics = "IMAGE_FILE_EXECUTABLE_IMAGE";
		break;
	case IMAGE_FILE_LINE_NUMS_STRIPPED:
		characteristics = "IMAGE_FILE_LINE_NUMS_STRIPPED";
		break;
	case IMAGE_FILE_LOCAL_SYMS_STRIPPED:
		characteristics = "IMAGE_FILE_LOCAL_SYMS_STRIPPED";
		break;
	case 0x0010:
		characteristics = "IMAGE_FILE_AGGRESSIVE_WS_TRIM";
		break;
	case IMAGE_FILE_LARGE_ADDRESS_AWARE:
		characteristics = "IMAGE_FILE_LARGE_ADDRESS_AWARE";
		break;
	case IMAGE_FILE_BYTES_REVERSED_LO:
		characteristics = "IMAGE_FILE_BYTES_REVERSED_LO";
		break;
	case IMAGE_FILE_32BIT_MACHINE:
		characteristics = "IMAGE_FILE_32BIT_MACHINE";
		break;
	case IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP:
		characteristics = "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP";
		break;
	case IMAGE_FILE_NET_RUN_FROM_SWAP:
		characteristics = "IMAGE_FILE_NET_RUN_FROM_SWAP";
		break;
	case IMAGE_FILE_SYSTEM:
		characteristics = "IMAGE_FILE_SYSTEM";
		break;
	case IMAGE_FILE_DLL:
		characteristics = "IMAGE_FILE_DLL";
		break;
	case IMAGE_FILE_UP_SYSTEM_ONLY:
		characteristics = "IMAGE_FILE_UP_SYSTEM_ONLY";
		break;
	case IMAGE_FILE_BYTES_REVERSED_HI:
		characteristics = "IMAGE_FILE_BYTES_REVERSED_HI";
		break;
	default:
		characteristics = NULL;
	}

	printf("\t\t%s\t\tMachine\n", machine);
	printf("\t\t0x%x\t\tNumber of Sections\n", imageNTHeaders->FileHeader.NumberOfSections);
	printf("\t\t0x%x\tTimestamp\n", imageNTHeaders->FileHeader.TimeDateStamp);
	printf("\t\t0x%x\t\tPointer to symbol table\n", imageNTHeaders->FileHeader.PointerToSymbolTable);
	printf("\t\t0x%x\t\tNumber of symbols\n", imageNTHeaders->FileHeader.NumberOfSymbols);
	printf("\t\t0x%x\t\tSize of optional header\n", imageNTHeaders->FileHeader.SizeOfOptionalHeader);
	if (!characteristics) {
		printf("\t\t0x%x\t\tCharacteristics\n", imageNTHeaders->FileHeader.Characteristics);
	}
	else {
		printf("\t\t%s\t\tCharacteristics\n", characteristics);
	}
}

void printOptionalHeader(PIMAGE_NT_HEADERS64 imageNTHeaders) {
	const char* subsystem;
	switch (imageNTHeaders->OptionalHeader.Subsystem) {
	case IMAGE_SUBSYSTEM_UNKNOWN:
		subsystem = "IMAGE_SUBSYSTEM_UNKNOWN";
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		subsystem = "IMAGE_SUBSYSTEM_NATIVE";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		subsystem = "IMAGE_SUBSYSTEM_WINDOWS_GUI";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		subsystem = "IMAGE_SUBSYSTEM_WINDOWS_CUI";
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		subsystem = "IMAGE_SUBSYSTEM_OS2_CUI";
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		subsystem = "IMAGE_SUBSYSTEM_POSIX_CUI";
		break;
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		subsystem = "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		subsystem = "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		subsystem = "IMAGE_SUBSYSTEM_EFI_APPLICATION";
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		subsystem = "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		subsystem = "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		subsystem = "IMAGE_SUBSYSTEM_EFI_ROM";
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		subsystem = "IMAGE_SUBSYSTEM_XBOX";
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		subsystem = "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
		break;
	default:
		subsystem = "UNKNOWN";
	}


	printf("\n******* OPTIONAL HEADER *******\n");
	if (imageNTHeaders->OptionalHeader.Magic == 0x10b) {
		printf("\t\tPE32\t\t\t\tMagic\n");
	}
	else if (imageNTHeaders->OptionalHeader.Magic == 0x20b) {
		printf("\t\tPE32+\t\t\t\tMagic\n");
	}
	else {
		printf("\t\tUNKNOWN\t\t\t\tMagic\n");
	}

	printf("\t\t0x%x\t\t\t\tMajor Linker Version\n", imageNTHeaders->OptionalHeader.MajorLinkerVersion);
	printf("\t\t0x%x\t\t\t\tMinor Linker Version\n", imageNTHeaders->OptionalHeader.MinorLinkerVersion);
	printf("\t\t0x%x\t\t\t\tSize of code\n", imageNTHeaders->OptionalHeader.SizeOfCode);
	printf("\t\t0x%x\t\t\t\tSize of initialized data\n", imageNTHeaders->OptionalHeader.SizeOfInitializedData);
	printf("\t\t0x%x\t\t\t\tSize of uninitialized data\n", imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
	printf("\t\t0x%x\t\t\t\tAddress of entry point\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t\t0x%x\t\t\t\tBase of Code\n", imageNTHeaders->OptionalHeader.BaseOfCode);
	cout << "\t\t0x" << std::hex << imageNTHeaders->OptionalHeader.ImageBase << "\t\t\tImage Base\n";
	printf("\t\t0x%x\t\t\t\tSection Alignment\n", imageNTHeaders->OptionalHeader.SectionAlignment);
	printf("\t\t0x%x\t\t\t\tFile Alignment\n", imageNTHeaders->OptionalHeader.FileAlignment);
	printf("\t\t0x%x\t\t\t\tMajor Operating System Version\n", imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t\t0x%x\t\t\t\tMinor Operating System Version\n", imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t\t0x%x\t\t\t\tMajor Image Version\n", imageNTHeaders->OptionalHeader.MajorImageVersion);
	printf("\t\t0x%x\t\t\t\tMinor Image Version\n", imageNTHeaders->OptionalHeader.MinorImageVersion);
	printf("\t\t0x%x\t\t\t\tMajor Subsystem Version\n", imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
	printf("\t\t0x%x\t\t\t\tMinor Subsystem Version\n", imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
	printf("\t\t0x%x\t\t\t\tWin32 Version Value\n", imageNTHeaders->OptionalHeader.Win32VersionValue);
	printf("\t\t0x%x\t\t\t\tSize Of Image\n", imageNTHeaders->OptionalHeader.SizeOfImage);
	printf("\t\t0x%x\t\t\t\tSize Of Headers\n", imageNTHeaders->OptionalHeader.SizeOfHeaders);
	printf("\t\t0x%x\t\t\t\tCheckSum\n", imageNTHeaders->OptionalHeader.CheckSum);
	printf("\t\t%s\tSubsystem\n", subsystem);
	printf("\t\t0x%x\t\t\t\tDllCharacteristics\n", imageNTHeaders->OptionalHeader.DllCharacteristics);
	cout << "\t\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfStackReserve << "\t\t\tSize Of Stack Reserve\n";
	cout << "\t\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfStackCommit << "\t\t\t\tSize Of Stack Commit\n";
	cout << "\t\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfHeapReserve << "\t\t\tSize Of Heap Reserve\n";
	cout << "\t\t0x" << std::hex << imageNTHeaders->OptionalHeader.SizeOfHeapCommit << "\t\t\t\tSize Of Heap Commit\n";
	printf("\t\t0x%x\t\t\t\tLoader Flags\n", imageNTHeaders->OptionalHeader.LoaderFlags);
	printf("\t\t0x%x\t\t\t\tNumber Of Rva And Sizes\n", imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);

	printf("\n\nDATA DIRECTORY\n");
	for (int i = 0; i < 16; i++) {
		const char* name;
		switch (i) {
		case 0:
			name = "Export table";
			break;
		case 1:
			name = "Import table";
			break;
		case 2:
			name = "Resource table";
			break;
		case 3:
			name = "Exception table";
			break;
		case 4:
			name = "Certificate Table";
			break;
		case 5:
			name = "Base Relocation Table";
			break;
		case 6:
			name = "Debug table";
			break;
		case 7:
			name = "Architecture specific";
			break;
		case 8:
			name = "RVA of global ptr";
			break;
		case 9:
			name = "TLS Table";
			break;
		case 10:
			name = "Load Config Table";
			break;
		case 11:
			name = "Bound Import";
			break;
		case 12:
			name = "Import Address Table";
			break;
		case 13:
			name = "Delay Import Descriptor";
			break;
		case 14:
			name = "CLR Runtime Header";
			break;
		case 15:
			name = "Reserved";
			break;
		default:
			name = "UNKNOWN";
		}
		DWORD address = imageNTHeaders->OptionalHeader.DataDirectory[i].VirtualAddress;
		DWORD size = imageNTHeaders->OptionalHeader.DataDirectory[i].Size;
		printf("\t\t%s with size 0x%x and virtual address 0x%x\n", name, size, address);
	}
}

void printSectionHeader(PIMAGE_SECTION_HEADER imageSectionHeader, DWORD numberOfSections) {
	PIMAGE_SECTION_HEADER temp = imageSectionHeader;
	printf("\n******* SECTION HEADERS *******\n\n");

	for (int i = 0; i < numberOfSections; i++) {
		printf("\tSection %d\n", i);
		printf("\t\t%s\t\tName\n", temp->Name);
		printf("\t\t0x%x\t\tVirtualSize\n", temp->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtualAddress\n", temp->VirtualAddress);
		printf("\t\t0x%x\t\tSizeOfRawData\n", temp->SizeOfRawData);
		printf("\t\t0x%x\t\tPointerToRawData\n", temp->PointerToRawData);
		printf("\t\t0x%x\t\tPointerToRelocations\n", temp->PointerToRelocations);
		printf("\t\t0x%x\t\tPointerToLinenumbers\n", temp->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumberOfRelocations\n", temp->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumberOfLinenumbers\n", temp->NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", temp->Characteristics);
		printf("\n------------------------------------------------------------\n\n");
		temp++;
	}
}

void printIAT(PIMAGE_SECTION_HEADER imageSectionHeader, DWORD numberOfSections, IMAGE_DATA_DIRECTORY importTable, DWORD fileBuffer) {
	PIMAGE_SECTION_HEADER temp = imageSectionHeader;
	PIMAGE_SECTION_HEADER targetSection = NULL;
	for (int i = 0; i < numberOfSections; i++) {
		if (importTable.VirtualAddress > temp->VirtualAddress && importTable.VirtualAddress < temp->VirtualAddress + temp->Misc.VirtualSize) {
			targetSection = temp;
			break;
		}
		temp++;
	}
	if (!targetSection) {
		printf("Failing to find IAT\n");
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)fileBuffer + targetSection->PointerToRawData + (importTable.VirtualAddress - targetSection->VirtualAddress));
	printf("\n******* IMPORT ADDRESS TABLE *******\n\n");
	for (; importDescriptor->Name != 0; importDescriptor++) {
		printf("\t\t%s\t\tName\n", (const char*)(fileBuffer + targetSection->PointerToRawData + (importDescriptor->Name - targetSection->VirtualAddress)));
		printf("\t\t0x%x\t\t\t\t\tName RVA\n", importDescriptor->Name);
		printf("\t\t0x%x\t\t\t\t\tOriginal First Thunk\n", importDescriptor->OriginalFirstThunk);
		printf("\t\t0x%x\t\t\t\t\tTimedate Stamp\n", importDescriptor->TimeDateStamp);
		printf("\t\t0x%x\t\t\t\t\tForwarder Chain\n", importDescriptor->ForwarderChain);
		printf("\t\t0x%x\t\t\t\t\tFirst Thunk\n", importDescriptor->FirstThunk);

		printf("\t\tImported function:\n");
		DWORD thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
		PIMAGE_THUNK_DATA64 thunkData = (PIMAGE_THUNK_DATA64)(fileBuffer + targetSection->PointerToRawData + (thunk - targetSection->VirtualAddress));
		for (; thunkData->u1.AddressOfData != 0; thunkData++) {
			if (thunkData->u1.AddressOfData > 0x80000000) {
				printf("\t\tOrdinal: %x\n", (DWORD)thunkData->u1.AddressOfData);
			}
			else {
				printf("\t\t  - %s\n", (const char*)(fileBuffer + targetSection->PointerToRawData + (thunkData->u1.AddressOfData - targetSection->VirtualAddress + 2)));
			}
		}
		printf("\n------------------------------------------------\n\n");
	}
}