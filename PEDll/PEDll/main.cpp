#include "main.h"



/*********************************************************************
*函数名：	GetDosHeader
*功能：	获得PE文件的DOS头
*参数：	csPath：PE文件路径。
*	pIDH：IMAGE_DOS_HEADER结构体指针
*返回值：	如果调用成功则返回true，否则返回false
**********************************************************************/
bool GetDosHeader(CString& csPath, IMAGE_DOS_HEADER* pIDH)
{
	CFile file(csPath, CFile::modeReadWrite);

	if(!file.Read((LPVOID)pIDH, sizeof(IMAGE_DOS_HEADER)))
	{
		AfxMessageBox(L"Failed to read DOS header!", MB_OK | MB_ICONSTOP);
		return false;
	}
	file.Close();

	return true;
}


/*********************************************************************
*函数名：	GetNtHeaders
*功能：	获得PE文件的NT头
*参数：	csPath：PE文件路径。
*	pINH：IMAGE_NT_HEADERS结构体指针
*返回值：	如果调用成功则返回true，否则返回false
**********************************************************************/
bool GetNtHeaders(CString& csPath, IMAGE_NT_HEADERS* pINH)
{
	//首先获得DOS头
	IMAGE_DOS_HEADER IDH;
	GetDosHeader(csPath, &IDH);

	//将文件指针移到e_lfanew所指向的位置，即NT头的位置
	CFile file(csPath, CFile::modeReadWrite);
	file.Seek(IDH.e_lfanew, CFile::begin);

	if(!file.Read((LPVOID)pINH, sizeof(IMAGE_NT_HEADERS)))
	{
		AfxMessageBox(L"Failed to read NT headers!", MB_OK | MB_ICONSTOP);
		return false;
	}
	file.Close();

	return true;
}


/*********************************************************************
*函数名：	GetSectionHeader
*功能：	获得PE文件的Section头
*参数：	csPath：PE文件路径。
*	pISH：IMAGE_SECTION_HEADER结构体指针
*返回值：	如果调用成功则返回true，否则返回false
**********************************************************************/
bool GetSectionHeader(CString& csPath, IMAGE_SECTION_HEADER pISH[])
{
	//获得DOS头
	IMAGE_NT_HEADERS INH;
	GetNtHeaders(csPath, &INH);

	//获得NT头
	IMAGE_DOS_HEADER IDH;
	GetDosHeader(csPath, &IDH);

	//初始化文件指针位置到e_lfanew + IMAGE_NT_HEADERS长度处
	LONGLONG pos = IDH.e_lfanew + sizeof(IMAGE_NT_HEADERS);

	CFile file(csPath, CFile::modeReadWrite);
	for(int i = 0; i <= (INH.FileHeader.NumberOfSections - 1); i++)
	{
		//移动文件指针
		file.Seek(pos, CFile::begin);

		//读取一个Section
		if(!file.Read((LPVOID)&pISH[i], sizeof(IMAGE_SECTION_HEADER)))
		{
			AfxMessageBox(TEXT("Failed to read IMAGE_SECTION_HEADER"), MB_OK | MB_ICONSTOP);
			file.Close();
			return false;
		}

		//文件指针加一个IMAGE_SECTION_HEADER的长度
		pos += sizeof(IMAGE_SECTION_HEADER);
	}
	file.Close();

	return true;
}