/*********************************************************************
*���ܣ�	���PE�ļ��������ؼ�ͷ����Ϣ��DOSͷ��NTͷ��Sectionͷ
*
*�޸�ʱ�䣺2010-1-14	
*�޸����ݣ����Ľӿڵķ���ֵ�������Ƿ���óɹ��ķ���
*
*���ߣ��������
**********************************************************************/



#ifndef MAIN_H
#define MAIN_H
#define _AFXDLL


#include "StdAfx.h"


bool GetDosHeader(CString& csPath, IMAGE_DOS_HEADER* pIDH);

bool GetNtHeaders(CString& csPath, IMAGE_NT_HEADERS* pINH);

bool GetSectionHeader(CString& csPath, IMAGE_SECTION_HEADER pISH[]);

#endif