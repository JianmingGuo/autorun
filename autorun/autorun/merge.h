#pragma once
#include <time.h>
#include <atlconv.h>
#include <windows.h>
#include <iostream>
#include <stdio.h>  
#include <tchar.h>  
#include <fstream>
#include <queue>
#include <vector>
#include <string>
#include "conio.h"
#include <string>

char* TCHARToChar(const TCHAR* pTchar)
{
	char* pChar = NULL;
#ifdef _UNICODE
	int nLen = wcslen(pTchar) + 1;
	pChar = new char[nLen * 2];
	WideCharToMultiByte(CP_ACP, 0, pTchar, nLen, pChar, 2 * nLen, NULL, NULL);
#else
	int nLen = strlen(pTchar) + 1;
	pChar = new char[nLen];
	memcpy(pChar, pTchar, nLen * sizeof(char));
#endif
	return pChar;
}

TCHAR* CharToTCHAR(const char* pChar)
{
	TCHAR* pTchar = NULL;
	int nLen = strlen(pChar) + 1;
#ifdef _UNICODE
	pTchar = new wchar_t[nLen];
	MultiByteToWideChar(CP_ACP, 0, pChar, nLen, pTchar, nLen);
#else
	pTchar = new char[nLen];
	wcsncp(pTChar, pChar, nLen * sizeof(char));
#endif
	return pTchar;
}

string TCHAR2STRING(TCHAR* str)
{
	std::string strstr;
	try
	{
		int iLen = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);

		char* chRtn = new char[iLen * sizeof(char)];

		WideCharToMultiByte(CP_ACP, 0, str, -1, chRtn, iLen, NULL, NULL);

		strstr = chRtn;
	}
	catch (std::exception e)
	{
	}

	return strstr;
}

