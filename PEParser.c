/*
* Brandon Arvanaghi
* Twitter: @arvanaghi
* PE32 Parser
*/

#include "stdio.h"
#include "string.h"
#include "Windows.h"

void checkValidExecutable(const char* executableNameUTF8) {
	FILE* pFile = fopen(executableNameUTF8, "rb");
	if (pFile == NULL) { fputs("File error", stderr); exit(1); }

	// Allocate a buffer to contain first 4 KB of executable size
	char* executableBuffer = malloc(2);
	if (executableBuffer == NULL) { fputs("Memory error", stderr); exit(2); }

	// Copy the first 2b of the executable into the buffer
	size_t result = fread(executableBuffer, 1, 2, pFile);
	if (result != 2) { fputs("Reading error", stderr); exit(3); }

	// If the first two bytes are not "MZ", or file does not end in .exe, .dll, .sys, then not valid executable
	const char* extension = strrchr(executableNameUTF8, '.');
	if (memcmp(executableBuffer, "MZ", 2) || (strcmp(extension, ".exe") && strcmp(extension, ".dll") && strcmp(extension, ".sys"))) {
		printf("[---] %s is not a valid executable.", executableNameUTF8);
		getchar();
		exit(-1);
	}

	// Close the file, free the buffer
	fclose(pFile);
	free(executableBuffer);
}

int wmain(int argc, wchar_t *argv[]) {
	if (argc < 2) {
		printf("[-] No executable path provided. Quitting.\n");
		printf("E.g. PEParser.exe \"C:\\Windows\\System32\\calc.exe\n\"");
		getchar();
		exit(-1);
	}

	LPCWSTR executableName = argv[1];

	// Convert WCHAR to char
	const char* executableNameUTF8[MAX_PATH];
	wcstombs(executableNameUTF8, argv[1], MAX_PATH);

	// Exits if first two bytes of file not "MZ", or file does not end in .exe, .dll, or .sys
	checkValidExecutable(executableNameUTF8);

	HANDLE hExecutable = CreateFile(executableName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hExecutable == INVALID_HANDLE_VALUE) {
		wprintf(L"[----] Could not find %s\n", executableName); 
		getchar();
		exit(-1);
	};

	HANDLE hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hExecutableMapping == 0) {
		CloseHandle(hExecutable);
		wprintf(L"[---] Could not map %s \n", executableName);
		getchar();
		exit(-1);
	}

	LPVOID pMappedBase = MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0, 0);
	if (pMappedBase == 0) {
		CloseHandle(hExecutableMapping);
		CloseHandle(hExecutable);
		wprintf(L"[---] Could not map view of %s\n", executableName);
		getchar();
		exit(-1);
	}

	wprintf(L"Executable name			: %s\n", executableName);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMappedBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)dosHeader + (DWORD)dosHeader->e_lfanew);

	/* 
	 DLLs and SYS device drivers are both subsets of executables in Windows. They all use the PE file structure. Two places to look to determine if regular executable, DLL, or SYS:
	1) To determine if DLL: struct IMAGE_NT_HEADERS -> struct IMAGE_FILE_HEADERS ->  WORD Characteristics
		0x0002 means EXE. DLLs and SYS device drivers are both subsets of executables, so they will both contain 0x0002 in Characteristics.
		If the executable is a DLL, Characteristics will be added by 0x2000. Sum of all the file's Characteristics becomes final Characteristics word value. 
		Can "and" with any individual Characteristic value to determine if file has that Characteristic added. 
	2) To determine if SYS: struct IMAGE_NT_HEADERS -> struct IMAGE_OPTIONAL_HEADER -> WORD Subsystem
		0001 means IMAGE_SUBSYSTEM_NATIVE, indicative of SYS file
	*/
	if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		// struct IMAGE_NT_HEADERS -> struct IMAGE_FILE_HEADERS ->  WORD Characteristics
		// If can AND with 0x2000, this executable is a DLL
		if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
			printf("Executable type			: Dynamic-link library (.dll)\n");
		// struct IMAGE_NT_HEADERS -> struct IMAGE_OPTIONAL_HEADER -> WORD Subsystem
		// If can AND with 1, this executable is a SYS device driver
		} else if (ntHeader->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_NATIVE) {
			printf("Executable type			: SYS device driver\n");
		// Else, it is just an executable
		} else { 
			printf("Executable type			: Regular executable (.exe)\n");
		}
	// This is not a proper executable file
	} else {
		wprintf("[---] %s is not a valid executable.", executableName);
		getchar();
		return FALSE;
	}
	
	printf("Size in memory of binary	: %#x\n", ntHeader->OptionalHeader.SizeOfImage);
	
	/* Gets section names
	* IMAGE_OPTIONAL_HEADER struct contains DWORD NumberOfSections
	* We already have a ptr to IMAGE_NT_HEADERS (where it starts). After this struct will be NumberOfSections structs of type SECTION.
	* By adding sizeof(ntHeader) struct to the ntHeader base address, we get a ptr to the first section.
	* We declare this ptr as type IMAGE_SECTION_HEADER so we can use array indexing to jump to the next section (e.g. header[0], ... header[numSections-1]).
	* Use a for loop between 0 and numSections to index each section in the PE. 
	*/
	WORD numSections = ntHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER header = (sizeof(*ntHeader) + (DWORD)ntHeader);

	printf("PE Sections			: ");
	for (int i = 0; i < numSections; ++i) {
		if (i == 0) {
			printf("[+] %s\n", header[i].Name);
		} else {
			printf("%+38s%s\n", "[+] ", header[i].Name);
		}
		
	}

	getchar();
	return 0;
}
