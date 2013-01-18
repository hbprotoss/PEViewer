/*********************************************************************
*功能：	获得PE文件的三个关键头的信息：DOS头，NT头，Section头
*
*修改时间：2010-1-14	
*修改内容：更改接口的返回值，增加是否调用成功的反馈
*
*作者：破碎虚空
**********************************************************************/



#ifndef MAIN_H
#define MAIN_H
#define _AFXDLL


#include "StdAfx.h"


bool GetDosHeader(CString& csPath, IMAGE_DOS_HEADER* pIDH);

bool GetNtHeaders(CString& csPath, IMAGE_NT_HEADERS* pINH);

bool GetSectionHeader(CString& csPath, IMAGE_SECTION_HEADER pISH[]);

#endif