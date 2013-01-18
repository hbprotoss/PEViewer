// PEViewer.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "PEViewer.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

typedef void (*GETDOS)(CString& csPath, IMAGE_DOS_HEADER* pIDH);
typedef void (*GETNT)(CString& csPath, IMAGE_NT_HEADERS* pINH);
typedef void (*GETSECTION)(CString& csPath, IMAGE_SECTION_HEADER pISH[]);
// Ψһ��Ӧ�ó������

CWinApp theApp;

using namespace std;

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(NULL);
	HMODULE hDll = LoadLibrary(TEXT("PEDll.dll"));
	GETDOS GetDosHeader = (GETDOS)GetProcAddress(hDll, "GetDosHeader");
	GETNT GetNtHeaders = (GETNT)GetProcAddress(hDll, "GetNtHeaders");
	GETSECTION GetSectionHeader = (GETSECTION)GetProcAddress(hDll, "GetSectionHeader");

	if (hModule != NULL)
	{
		// ��ʼ�� MFC ����ʧ��ʱ��ʾ����
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			// TODO: ���Ĵ�������Է���������Ҫ
			_tprintf(_T("����: MFC ��ʼ��ʧ��\n"));
			nRetCode = 1;
		}
		else
		{
			// TODO: �ڴ˴�ΪӦ�ó������Ϊ��д���롣
			cout << "PEViewer will now open an OpenFile dialog for you to choose the PE file"
				<< " you want to analyse. " << "Press any key to continue...\n";
			system("pause>nul");

			//ѡ���ļ�
			static TCHAR BASED_CODE szFilter[] = TEXT("All PE Files(*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys");
			CString csFile;
			CFileDialog   filedlg(TRUE, NULL, NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
				szFilter);
			if(IDOK == filedlg.DoModal())
			{
				csFile = filedlg.GetPathName();

				//���IMAGE_DOS_HEADER�ṹ
				IMAGE_DOS_HEADER IDH;
				GetDosHeader(csFile, &IDH);

				//���IMAGE_NT_HEADERS�ṹ
				IMAGE_NT_HEADERS INH;
				GetNtHeaders(csFile, &INH);

				//����IMAGE_SECTION_HEADER
				IMAGE_SECTION_HEADER *ISH = new IMAGE_SECTION_HEADER[INH.FileHeader.NumberOfSections];
				GetSectionHeader(csFile, ISH);
				

				system("cls");
				//���IMAGE_NT_HEADERS�ṹ����
				cout << "---------------Signature--------------\n";
				cout << "Signature: " << INH.Signature << endl;
				cout << "---------------IMAGE_FILE_HEADER--------------\n";
				cout << "Machine: " << INH.FileHeader.Machine << endl;
				cout << "NumberOfSections: " << INH.FileHeader.NumberOfSections << endl;
				cout << "TimeDataStamp: " << INH.FileHeader.TimeDateStamp << endl;
				cout << "PointerToSymbolTable: " << INH.FileHeader.PointerToSymbolTable << endl;
				cout << "NumberOfSymbols: " << INH.FileHeader.NumberOfSymbols << endl;
				cout << "SizeOfOpitionalHeader: " << INH.FileHeader.SizeOfOptionalHeader << endl;
				cout << "Characteristics: " << INH.FileHeader.Characteristics << endl;
				cout << "---------------IMAGE_OPTIONAL_HEADER(Standard Area)--------------\n";
				cout << "Magic: 0x" << hex << INH.OptionalHeader.Magic << endl;
				cout << "MajorLinkerVersion: "  << dec << INH.OptionalHeader.MajorLinkerVersion << endl;
				cout << "MinorLinkerVersion: " << INH.OptionalHeader.MinorLinkerVersion << endl;
				cout << "SizeOfCode: " << INH.OptionalHeader.SizeOfCode << endl;
				cout << "SizeOfInitializedData: " << INH.OptionalHeader.SizeOfInitializedData << endl;
				cout << "SizeOfUninitializedData: " << INH.OptionalHeader.SizeOfUninitializedData << endl;
				cout << "AddressOfEntryPoint: 0x" << hex << INH.OptionalHeader.AddressOfEntryPoint << endl;
				cout << "BaseOfCode: 0x" << hex << INH.OptionalHeader.BaseOfCode << endl;
				cout << "BaseOfData: 0x" << hex << INH.OptionalHeader.BaseOfData << endl;
				cout << "---------------IMAGE_OPTIONAL_HEADER(NT Opitional Area)--------------\n";
				cout << "ImageBase: 0x" << hex << INH.OptionalHeader.ImageBase << endl;
				cout << "SectioAlignment: " << dec << INH.OptionalHeader.SectionAlignment << endl;
				cout << "FileAlignment: " << INH.OptionalHeader.FileAlignment << endl;
				cout << "MajorOperatingSystemVersion: " << INH.OptionalHeader.MajorOperatingSystemVersion << endl;
				cout << "MinorOperatingSystemVersion: " << INH.OptionalHeader.MinorOperatingSystemVersion << endl;
				cout << "MajorImageVersion: " << INH.OptionalHeader.MajorImageVersion << endl;
				cout << "MinorImageVersion: " << INH.OptionalHeader.MinorImageVersion << endl;
				cout << "MajorSubsystemVersion: " << INH.OptionalHeader.MajorSubsystemVersion << endl;
				cout << "MinorSubSystemVersion: " << INH.OptionalHeader.MinorSubsystemVersion << endl;
				cout << "Win32VersionValue: " << INH.OptionalHeader.Win32VersionValue << endl;
				cout << "SizeOfImage: " << INH.OptionalHeader.SizeOfImage << endl;
				cout << "SizeOfHeaders: " << INH.OptionalHeader.SizeOfHeaders << endl;
				cout << "CheckSum: " << INH.OptionalHeader.CheckSum << endl;
				cout << "SubSystem: " << INH.OptionalHeader.Subsystem << endl;
				cout << "DllCharacteristics: " << INH.OptionalHeader.DllCharacteristics << endl;
				cout << "SizeOfStackReserve: " << INH.OptionalHeader.SizeOfStackReserve << endl;
				cout << "SizeOfStackCommit: " << INH.OptionalHeader.SizeOfStackCommit << endl;
				cout << "SizeOfHeapReserve: " << INH.OptionalHeader.SizeOfHeapReserve << endl;
				cout << "SizeOfHeapCommit: " << INH.OptionalHeader.SizeOfHeapCommit << endl;

				cout << "---------------Sections---------------\n";

				//�������Ϣ
				for(int i = 0; i <= (INH.FileHeader.NumberOfSections - 1); i++)
				{
					cout << ISH[i].Name << ": PhysicalAddress: 0x" << hex << ISH[i].Misc.PhysicalAddress 
						<< "     VirtualSize: " << dec << ISH[i].Misc.VirtualSize << endl;
				}

				cout  << endl << "Press any key to continue...\n";
				system("pause>nul");

				delete [] ISH;
			}
		}
	}
	else
	{
		// TODO: ���Ĵ�������Է���������Ҫ
		_tprintf(_T("����: GetModuleHandle ʧ��\n"));
		nRetCode = 1;
	}
	system("pause");
	return nRetCode;
}
