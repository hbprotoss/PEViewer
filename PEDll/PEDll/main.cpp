#include "main.h"



/*********************************************************************
*��������	GetDosHeader
*���ܣ�	���PE�ļ���DOSͷ
*������	csPath��PE�ļ�·����
*	pIDH��IMAGE_DOS_HEADER�ṹ��ָ��
*����ֵ��	������óɹ��򷵻�true�����򷵻�false
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
*��������	GetNtHeaders
*���ܣ�	���PE�ļ���NTͷ
*������	csPath��PE�ļ�·����
*	pINH��IMAGE_NT_HEADERS�ṹ��ָ��
*����ֵ��	������óɹ��򷵻�true�����򷵻�false
**********************************************************************/
bool GetNtHeaders(CString& csPath, IMAGE_NT_HEADERS* pINH)
{
	//���Ȼ��DOSͷ
	IMAGE_DOS_HEADER IDH;
	GetDosHeader(csPath, &IDH);

	//���ļ�ָ���Ƶ�e_lfanew��ָ���λ�ã���NTͷ��λ��
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
*��������	GetSectionHeader
*���ܣ�	���PE�ļ���Sectionͷ
*������	csPath��PE�ļ�·����
*	pISH��IMAGE_SECTION_HEADER�ṹ��ָ��
*����ֵ��	������óɹ��򷵻�true�����򷵻�false
**********************************************************************/
bool GetSectionHeader(CString& csPath, IMAGE_SECTION_HEADER pISH[])
{
	//���DOSͷ
	IMAGE_NT_HEADERS INH;
	GetNtHeaders(csPath, &INH);

	//���NTͷ
	IMAGE_DOS_HEADER IDH;
	GetDosHeader(csPath, &IDH);

	//��ʼ���ļ�ָ��λ�õ�e_lfanew + IMAGE_NT_HEADERS���ȴ�
	LONGLONG pos = IDH.e_lfanew + sizeof(IMAGE_NT_HEADERS);

	CFile file(csPath, CFile::modeReadWrite);
	for(int i = 0; i <= (INH.FileHeader.NumberOfSections - 1); i++)
	{
		//�ƶ��ļ�ָ��
		file.Seek(pos, CFile::begin);

		//��ȡһ��Section
		if(!file.Read((LPVOID)&pISH[i], sizeof(IMAGE_SECTION_HEADER)))
		{
			AfxMessageBox(TEXT("Failed to read IMAGE_SECTION_HEADER"), MB_OK | MB_ICONSTOP);
			file.Close();
			return false;
		}

		//�ļ�ָ���һ��IMAGE_SECTION_HEADER�ĳ���
		pos += sizeof(IMAGE_SECTION_HEADER);
	}
	file.Close();

	return true;
}