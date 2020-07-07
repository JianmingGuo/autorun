#pragma once
#pragma execution_character_set("utf-8")

#include <iostream>
#include <assert.h>
#include "windows.h"
#include "tchar.h"
#include "conio.h"
#include "stdio.h"
#include <taskschd.h>
#include <string>
#include<vector>
#include<io.h>
#include <fstream>
#include <map>
#include "Winver.h"
#include "atrribute.h"


#pragma once
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <map>

#include <Wincrypt.h>
#include <stdlib.h>
#include <Softpub.h>

#include <vector>

#include <comdef.h>
#include <taskschd.h>


#pragma comment(lib, "version.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "taskschd.lib")
using namespace std;
#pragma comment(lib, "version")  	

string Cutstring1(char* route);
string Cutstring2(string route);

int get_files(string fileFolderPath, string fileExtension, vector<string>& file)
{
	std::string fileFolder = fileFolderPath + "\\*" + fileExtension;
	std::string fileName;
	struct _finddata_t fileInfo;
	long long findResult = _findfirst(fileFolder.c_str(), &fileInfo);
	if (findResult == -1)
	{
		_findclose(findResult);
		return 0;
	}
	bool flag = 0;

	do
	{
		fileName = fileFolderPath + "\\" + fileInfo.name;
		if (fileInfo.attrib == _A_ARCH)
		{
			file.push_back(fileName);
		}
	} while (_findnext(findResult, &fileInfo) == 0);

	_findclose(findResult);
}


std::string GetTaskPath(const char* Filename)
{
	int Begin, End;

	string X, Y;
	string Line;
	static char num = 0;
	ifstream inFile;

	inFile.open(Filename);	//打开文件用于读取数据。如果文件不存在，则打开出错。
	if (!inFile.is_open())			//判断文件是否成功打开
	{
		cout << "Error opening file" << endl;
		return "";
	}

	while (!inFile.eof())
	{
		getline(inFile, Line);					//获取一行的数据，存放到Line中
		Begin = Line.find("<Command>");
		if (Begin != string::npos)//若该行中存在"x="的字符
		{
			Begin += 8;
			if (Begin == Line.find('>'))		//若"x="的下一个字符是'"'，则定位到了数据开始的位置
			{
				End = Line.find('<', Begin + 1);//定位x坐标文本的结束下标
				X = Line.substr(Begin + 1, (End - (Begin + 1)));//获取x坐标的文本信息
			}
		}
	}
	inFile.close();

	return X;
}

namespace BaseFlow
{
	namespace Attribute
	{
		bool	GetFileDescription(const std::string& szModuleName, std::string& RetStr);
		bool	GetFileVersion(const std::string& szModuleName, std::string& RetStr);
		bool	GetInternalName(const std::string& szModuleName, std::string& RetStr);
		bool	GetCompanyName(const std::string& szModuleName, std::string& RetStr);
		bool	GetLegalCopyright(const std::string& szModuleName, std::string& RetStr);
		bool	GetOriginalFilename(const std::string& szModuleName, std::string& RetStr);
		bool	GetProductName(const std::string& szModuleName, std::string& RetStr);
		bool	GetProductVersion(const std::string& szModuleName, std::string& RetStr);
	}
}

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

bool QueryValue(const std::string& ValueName, const std::string& szModuleName, std::string& RetStr)
{
	bool bSuccess = FALSE;
	BYTE* m_lpVersionData = NULL;
	DWORD   m_dwLangCharset = 0;
	CHAR* tmpstr = NULL;

	do
	{
		if (!ValueName.size() || !szModuleName.size())
			break;

		DWORD dwHandle;
		// 判断系统能否检索到指定文件的版本信息
		DWORD dwDataSize = ::GetFileVersionInfoSizeA((LPCSTR)szModuleName.c_str(), &dwHandle);
		if (dwDataSize == 0)
			break;

		m_lpVersionData = new (std::nothrow) BYTE[dwDataSize];// 分配缓冲区
		if (NULL == m_lpVersionData)
			break;

		// 检索信息
		if (!::GetFileVersionInfoA((LPCSTR)szModuleName.c_str(), dwHandle, dwDataSize,
			(void*)m_lpVersionData))
			break;

		UINT nQuerySize;
		DWORD* pTransTable;
		// 设置语言
		if (!::VerQueryValueA(m_lpVersionData, "\\VarFileInfo\\Translation", (void**)&pTransTable, &nQuerySize))
			break;

		m_dwLangCharset = MAKELONG(HIWORD(pTransTable[0]), LOWORD(pTransTable[0]));
		if (m_lpVersionData == NULL)
			break;

		tmpstr = new (std::nothrow) CHAR[128];// 分配缓冲区
		if (NULL == tmpstr)
			break;
		sprintf_s(tmpstr, 128, "\\StringFileInfo\\%08lx\\%s", m_dwLangCharset, ValueName.c_str());
		LPVOID lpData;

		// 调用此函数查询前需要先依次调用函数GetFileVersionInfoSize和GetFileVersionInfo
		if (::VerQueryValueA((void*)m_lpVersionData, tmpstr, &lpData, &nQuerySize))
			RetStr = (char*)lpData;

		bSuccess = TRUE;
	} while (FALSE);

	// 销毁缓冲区
	if (m_lpVersionData)
	{
		delete[] m_lpVersionData;
		m_lpVersionData = NULL;
	}
	if (tmpstr)
	{
		delete[] tmpstr;
		tmpstr = NULL;
	}

	return bSuccess;
}

std::string Cutstring1(char* route) {

	std::string cutted;
	cutted = route;
	for (int i = 0; i < cutted.length(); i++) {
		if (route[i] == '"') {
			cutted.erase(i, 1);
		}
		if (route[i] == '.' && route[i + 1] == 'e' && route[i + 2] == 'x' && route[i + 3] == 'e') {
			cutted.erase(i + 4);
			return cutted;
		}
		if (route[i] == '.' && route[i + 1] == 'E' && route[i + 2] == 'X' && route[i + 3] == 'E') {
			cutted.erase(i + 4);
			return cutted;
		}
	}

	return cutted;
}

std::string Cutstring2(std::string route) {

	for (int i = 0; i < route.length(); i++) {
		if (route[i] == '"') {
			route.erase(i, 1);
		}
	}

	return route;
}


bool	BaseFlow::Attribute::GetFileDescription(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("FileDescription", szModuleName, RetStr);
};   

bool	BaseFlow::Attribute::GetCompanyName(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("CompanyName", szModuleName, RetStr);
};	   //获取公司名称

map<int, char*> read_subitem(HKEY aim_rootkey, LPCTSTR aim_key)
{
	HKEY cpp_key;
	map<int, char*> subitem;
	int len = 0;
	//cout << "---读取子键---" << endl;
	if (ERROR_SUCCESS == RegOpenKeyEx(aim_rootkey, aim_key, 0, KEY_READ, &cpp_key)) {
		DWORD dwIndex = 0, NameSize, NameCnt, NameMaxLen, Type;
		DWORD KeySize, KeyCnt, KeyMaxLen, DateSize, MaxDateLen;
		if (ERROR_SUCCESS == RegQueryInfoKey(cpp_key, NULL, NULL, 0, &KeyCnt, &KeyMaxLen, NULL, &NameCnt, &NameMaxLen, &MaxDateLen, NULL, NULL)) {
			//cout << "共有" << KeyCnt << "个子键" << endl;
			for (DWORD dwIndex = 0; dwIndex < KeyCnt; dwIndex++)
			{
				KeySize = KeyMaxLen + 1;
				char* szKeyName = (char*)malloc(KeySize);
				RegEnumKeyEx(cpp_key, dwIndex, szKeyName, &KeySize, NULL, NULL, NULL, NULL);
				//cout << szKeyName << endl;

				subitem[len] = szKeyName;
				len++;
			}
		}
		else {
			cout << "读取子键失败！" << endl;
		}
	}
	else {
		cout << "打开注册表失败！" << endl;
	}
	RegCloseKey(cpp_key);//关闭句柄
	//cout << "---读取子键结束---" << endl;

	return subitem;
}

map<char*, LPBYTE> read_value(HKEY aim_rootkey, LPCUTSTR key_data)
{
	HKEY cpp_key;
	map<char*, LPBYTE> mymap;

	if (ERROR_SUCCESS == RegOpenKeyEx(aim_rootkey, key_data, 0, KEY_READ, &cpp_key)) {
		DWORD dwIndex = 0, NameSize, NameCnt, NameMaxLen, Type;
		DWORD KeySize, KeyCnt, KeyMaxLen, DateSize, MaxDateLen;
		if (ERROR_SUCCESS == RegQueryInfoKey(cpp_key, NULL, NULL, 0, &KeyCnt, &KeyMaxLen, NULL, &NameCnt, &NameMaxLen, &MaxDateLen, NULL, NULL)) {
			//cout << "共有" << NameCnt << "个键值" << endl;
			for (DWORD dwIndex = 0; dwIndex < NameCnt; dwIndex++)
			{
				DateSize = MaxDateLen + 1;
				NameSize = NameMaxLen + 1;
				char* szValueName = (char*)malloc(NameSize);
				LPBYTE szValueDate = (LPBYTE)malloc(DateSize);
				RegEnumValue(cpp_key, dwIndex, szValueName, &NameSize, NULL, &Type, szValueDate, &DateSize);
				//cout << "类型：" << Type << " 名称：" << szValueName << " 数据：" << szValueDate << endl;
				mymap[szValueName] = szValueDate;

			}

		}
		else {
			cout << "读取子键失败！" << endl;
		}
	}
	else {
		cout << "打开注册表失败！" << endl;
	}

	return mymap;
}

string** enumLogon(LPCTSTR SubKey, HKEY Sheet)
{

	HKEY hKey;

	if (RegOpenKeyEx(Sheet, SubKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		return {};
	}
#define NAME_LEN 256
	char szValueName[NAME_LEN];
	BYTE szPortName[NAME_LEN];
	LONG status;
	DWORD dwIndex = 0;
	DWORD dwSizeValueName = 256;
	DWORD dwSizeofPortName = 256;
	DWORD Type;
	dwSizeValueName = NAME_LEN;
	dwSizeofPortName = NAME_LEN;
	std::string  Company, Description, Name;
	/*const char*** logonitem;
	logonitem = new const char** [256];
	for (int i = 0; i < 256; i++) {
		logonitem[i] = new const char*[4];


	}*/
	string** logonitem;
	logonitem = new string * [256];
	for (int i = 0; i < 256; i++)
	{
		logonitem[i] = new string[4];
	}
	int i = 0;
	do
	{
		status = RegEnumValue(hKey, dwIndex++, szValueName, &dwSizeValueName, NULL, &Type, szPortName, &dwSizeofPortName);
		if ((status == ERROR_SUCCESS) && strlen(szValueName) != 0)
		{
			//printf("Entry = %s \n", szValueName);

			logonitem[i][0] = szValueName;
			//cout << logonitem[i][0]<<endl;
			char* p = new char[sizeof(szPortName)];
			memcpy(p, szPortName, sizeof(szPortName));
			p[sizeof(szPortName)] = 0;
			//cout << "Image Path = " << Cutstring2(Cutstring1(p)) << endl;

			logonitem[i][3] = Cutstring2(Cutstring1(p));
			BaseFlow::Attribute::GetCompanyName(Cutstring2(Cutstring1(p)), Company);
			BaseFlow::Attribute::GetFileDescription(Cutstring2(Cutstring1(p)), Description);
			BaseFlow::Attribute::GetProductName(Cutstring2(Cutstring1(p)), Name);
			logonitem[i][2] = Company;
			logonitem[i][1] = Description;
			i++;
			//cout << "Company = " << Company << endl;
			//cout << "Description = " << Description << endl;
			//printf("\n");

		}
		//每读取一次dwSizeValueName和dwSizeofPortName都会被修改
		//注意一定要重置,否则会出现很离奇的错误,本人就试过因没有重置,出现读不了COM大于10以上的串口
		dwSizeValueName = NAME_LEN;
		dwSizeofPortName = NAME_LEN;
	} while ((status != ERROR_NO_MORE_ITEMS));
	RegCloseKey(hKey);
	return logonitem;
}

char* stringToLPCTSTR(string sFrom)

{

	_TCHAR* sBuff = new _TCHAR[sFrom.length() + 2];

	int iLength = 0;

	iLength = wsprintf(sBuff, sFrom.c_str());

	sBuff[iLength + 1] = '/0';

	return sBuff;

}


static string** serviceitem;


int autoStartService(char* subkey, LPCSTR path, int sum)
{
	/* 给出一个子键的路径，通过读它的键值对判断是否为自启动项，如果是则输出相应信息 */
	HKEY key;
	// 打开注册表
	if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key)) {
		// 读取键值对
		DWORD name_size, name_cnt, name_max_len, type, key_cnt, key_max_len, data_size, data_max_len;
		if (ERROR_SUCCESS == RegQueryInfoKey(key, NULL, NULL, 0, &key_cnt, &key_max_len, NULL, &name_cnt, &name_max_len, &data_max_len, NULL, NULL)) {
			// 枚举键值
			int t, flag = 0;
			char* img_pth = new char[1024];
			std::string  Company, Description;

			for (DWORD dwIndex = 0; dwIndex < name_cnt; dwIndex++) {
				data_size = data_max_len + 1;
				name_size = name_max_len + 1;
				char* name = new char[name_size];
				LPBYTE data = (LPBYTE)malloc(data_size);
				RegEnumValue(key, dwIndex, name, &name_size, NULL, &type, data, &data_size);
				if (strcmp(name, "ImagePath") == 0) {
					for (DWORD i = 0; i < data_size; i++) {
						img_pth[i] = data[i];
					}
					flag++;
				}
				else if (strcmp(name, "Start") == 0) {
					t = static_cast<int>(data[0]);
					if (t != 3 && t != 4)
						flag++;
					else
						flag = -10;
				}
				else if (strcmp(name, "Type") == 0) {
					t = static_cast<int>(data[0]);
					if (t != 1 && t != 2)
						flag++;
					else
						flag = -10;
				}
				if (flag == 3) {
					/*---------------------*/
					BaseFlow::Attribute::GetFileDescription(Cutstring2(Cutstring1(img_pth)), Description);
					BaseFlow::Attribute::GetCompanyName(Cutstring2(Cutstring1(img_pth)), Company);
					if (Description.length() > 1) {


						serviceitem[sum][0] = subkey;
						serviceitem[sum][3] = Cutstring2(Cutstring1(img_pth));
						serviceitem[sum][2] = Company;
						serviceitem[sum][1] = Description;





						//printf("Entry = %s \n", subkey);
						//cout << "Image Path = " << Cutstring2(Cutstring1(img_pth)) << endl;
						//cout << "Company = " << Company << endl;
						//cout << "Description = " << Description << endl;
						//printf("\n");
						/*---------------------*/
						return 1;
					}
					return 0;

				}
				else if (flag < 0) {
					return 0;
				}
			}
		}
	}
	return 0;
}

int autoStartDriver(char* subkey, LPCSTR path)
{
	/* 给出一个子键的路径，通过读它的键值对判断是否为自启动项，如果是则输出相应信息 */
	HKEY key;
	// 打开注册表
	if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key)) {
		// 读取键值对
		DWORD name_size, name_cnt, name_max_len, type, key_cnt, key_max_len, data_size, data_max_len;
		if (ERROR_SUCCESS == RegQueryInfoKey(key, NULL, NULL, 0, &key_cnt, &key_max_len, NULL, &name_cnt, &name_max_len, &data_max_len, NULL, NULL)) {
			// 枚举键值
			int t, flag = 0;
			char* img_pth = new char[1024];
			std::string  Company, Description;

			for (DWORD dwIndex = 0; dwIndex < name_cnt; dwIndex++) {
				data_size = data_max_len + 1;
				name_size = name_max_len + 1;
				char* name = new char[name_size];
				LPBYTE data = (LPBYTE)malloc(data_size);
				RegEnumValue(key, dwIndex, name, &name_size, NULL, &type, data, &data_size);
				if (strcmp(name, "ImagePath") == 0) {
					for (DWORD i = 0; i < data_size; i++) {
						img_pth[i] = data[i];
					}
					flag++;
				}

				else if (strcmp(name, "Type") == 0) {
					t = static_cast<int>(data[0]);
					if (t == 1)
						flag++;
					else
						flag = -10;
				}
				if (flag == 2) {
					/*---------------------*/
					BaseFlow::Attribute::GetFileDescription(Cutstring2(Cutstring1(img_pth)), Description);
					BaseFlow::Attribute::GetCompanyName(Cutstring2(Cutstring1(img_pth)), Company);
					if (Description.length() > 1) {
						printf("Entry = %s \n", subkey);
						cout << "Image Path = " << Cutstring2(Cutstring1(img_pth)) << endl;
						cout << "Company = " << Company << endl;
						cout << "Description = " << Description << endl;
						printf("\n");
						/*---------------------*/
						return 1;
					}
					return 0;

				}
				else if (flag < 0) {
					return 0;
				}
			}
		}
	}
	return 0;
}



DWORD read_type(HKEY aim_rootkey, LPCSTR key_data)
{
	HKEY cpp_key;
	DWORD type;
	DWORD dwtype = REG_DWORD;
	DWORD dwvalue;
	long ret;
	ret = RegOpenKeyEx(aim_rootkey, key_data, 0, KEY_QUERY_VALUE, &cpp_key);
	if (ret == ERROR_SUCCESS)
		ret = RegQueryValueEx(cpp_key, "Type", 0, &dwtype, (LPBYTE)&type, &dwvalue);
	if (ret == ERROR_SUCCESS)
		RegCloseKey(cpp_key);
	//cout << type << endl;
	return type;
}

LPBYTE read_imagepath(HKEY aim_rootkey, LPCSTR key_data)
{
	HKEY cpp_key;
	DWORD dwtype = 0;
	LPBYTE lpvalue = NULL;
	DWORD dwsize = 0;

	long ret;
	ret = RegOpenKeyEx(aim_rootkey, key_data, 0, KEY_QUERY_VALUE, &cpp_key);
	if (ret == ERROR_SUCCESS)
	{
		RegQueryValueEx(cpp_key, _T("ImagePath"), 0, &dwtype, lpvalue, &dwsize);
		lpvalue = (LPBYTE)malloc(dwsize);
		ret = RegQueryValueEx(cpp_key, _T("ImagePath"), 0, &dwtype, lpvalue, &dwsize);
		RegCloseKey(cpp_key);
	}

	//cout << lpvalue << endl;
	return lpvalue;
}

LPBYTE read_description(HKEY aim_rootkey, LPCSTR key_data)
{
	HKEY cpp_key;
	DWORD dwtype = 0;
	LPBYTE lpvalue = NULL;
	DWORD dwsize = 0;

	long ret;
	ret = RegOpenKeyEx(aim_rootkey, key_data, 0, KEY_QUERY_VALUE, &cpp_key);
	if (ret == ERROR_SUCCESS)
	{
		RegQueryValueEx(cpp_key, _T("Description"), 0, &dwtype, lpvalue, &dwsize);
		lpvalue = (LPBYTE)malloc(dwsize);
		ret = RegQueryValueEx(cpp_key, _T("Description"), 0, &dwtype, lpvalue, &dwsize);
		RegCloseKey(cpp_key);
	}

	//cout << lpvalue << endl;
	return lpvalue;
}

LPBYTE read_objectname(HKEY aim_rootkey, LPCSTR key_data)
{
	HKEY cpp_key;
	DWORD dwtype = 0;
	LPBYTE lpvalue = NULL;
	DWORD dwsize = 0;

	long ret;
	ret = RegOpenKeyEx(aim_rootkey, key_data, 0, KEY_QUERY_VALUE, &cpp_key);
	if (ret == ERROR_SUCCESS)
	{
		RegQueryValueEx(cpp_key, _T("ObjectName"), 0, &dwtype, lpvalue, &dwsize);
		lpvalue = (LPBYTE)malloc(dwsize);
		ret = RegQueryValueEx(cpp_key, _T("ObjectName"), 0, &dwtype, lpvalue, &dwsize);
		RegCloseKey(cpp_key);
	}

	//cout << lpvalue << endl;
	return lpvalue;
}

map<int, char*> read_subitem(HKEY aim_rootkey, LPCTSTR aim_key)
{
	HKEY cpp_key;
	map<int, char*> subitem;
	int len = 0;
	//cout << "---读取子键---" << endl;
	if (ERROR_SUCCESS == RegOpenKeyEx(aim_rootkey, aim_key, 0, KEY_READ, &cpp_key)) {
		DWORD dwIndex = 0, NameSize, NameCnt, NameMaxLen, Type;
		DWORD KeySize, KeyCnt, KeyMaxLen, DateSize, MaxDateLen;
		if (ERROR_SUCCESS == RegQueryInfoKey(cpp_key, NULL, NULL, 0, &KeyCnt, &KeyMaxLen, NULL, &NameCnt, &NameMaxLen, &MaxDateLen, NULL, NULL)) {
			//cout << "共有" << KeyCnt << "个子键" << endl;
			for (DWORD dwIndex = 0; dwIndex < KeyCnt; dwIndex++)
			{
				KeySize = KeyMaxLen + 1;
				char* szKeyName = (char*)malloc(KeySize);
				RegEnumKeyEx(cpp_key, dwIndex, szKeyName, &KeySize, NULL, NULL, NULL, NULL);
				//cout << szKeyName << endl;

				subitem[len] = szKeyName;
				len++;
			}
		}
		else {
			cout << "读取子键失败！" << endl;
		}
	}
	else {
		cout << "打开注册表失败！" << endl;
	}
	RegCloseKey(cpp_key);//关闭句柄
	//cout << "---读取子键结束---" << endl;

	return subitem;
}
string** service()
{
	HKEY rootkey = HKEY_LOCAL_MACHINE;
	LPCSTR keydata = "SYSTEM\\CurrentControlSet\\Services";

	map<int, char*> subitem;
	map<char*, LPBYTE> value;

	subitem = read_subitem(rootkey, keydata);
	string item;
	string tmpdata;
	DWORD type;

	string** serviceitem;
	serviceitem = new string * [256];
	for (int i = 0; i < 256; i++)
	{
		serviceitem[i] = new string[4];
	}
	int i = 0;

	for (map<int, char*>::iterator it = subitem.begin(); it != subitem.end(); ++it)
	{
		//cout << it->first << "->" << it->second << endl;

		item = it->second;
		tmpdata = "SYSTEM\\CurrentControlSet\\Services\\" + item;
		//cout << tmpdata<<endl;
		LPCSTR test = tmpdata.c_str();
		LPBYTE objectname, description, imagepath;

		type = read_type(rootkey, test);
		if (type >= 16)
		{

			objectname = read_objectname(rootkey, test);
			description = read_description(rootkey, test);
			imagepath = read_imagepath(rootkey, test);
			//cout << objectname << '\t' << description << '\t' << imagepath << endl;
			////////////////////////////////////////////////////////////////////////////////////
			i++;
		}
	}
	return serviceitem;
}

string** driver()
{
	HKEY rootkey = HKEY_LOCAL_MACHINE;
	LPCSTR keydata = "SYSTEM\\CurrentControlSet\\Services";

	map<int, char*> subitem;
	map<char*, LPBYTE> value;

	subitem = read_subitem(rootkey, keydata);
	string item;
	string tmpdata;
	DWORD type;
	int len = 0;

	string** driveritem;
	driveritem = new string * [1024];
	for (int i = 0; i < 1024; i++)
	{
		driveritem[i] = new string[4];
	}
	int i = 0;

	for (map<int, char*>::iterator it = subitem.begin(); it != subitem.end(); ++it)
	{
		//cout << it->first << "->" << it->second << endl;

		item = it->second;
		tmpdata = "SYSTEM\\CurrentControlSet\\Services\\" + item;
		//cout << tmpdata<<endl;
		LPCSTR test = tmpdata.c_str();
		LPBYTE objectname, description, imagepath;

		type = read_type(rootkey, test);
		if (type < 16)
		{
			objectname = read_objectname(rootkey, test);
			description = read_description(rootkey, test);
			imagepath = read_imagepath(rootkey, test);
			len = len + 1;
			//cout << "test" << endl;

			driveritem[i][0] = item;
			char* s2 = (char*)description;

			char* s3 = (char*)imagepath;
			driveritem[i][3] = s3;
			driveritem[i][2] = s2;
			i++;
			//cout << s << endl;
			//cout << len << '\t' << objectname << '\t' << description << '\t' << imagepath << endl;
		}
	}
	return driveritem;
}
void enumService(LPCTSTR SubKey, HKEY Sheet)
{
	HKEY hKey;
	HKEY hKey1;
	DWORD dwType = REG_SZ;
	DWORD dwLen = MAX_PATH;
	wchar_t data[MAX_PATH];
	int sum = 0;

	serviceitem = new string * [256];
	for (int i = 0; i < 256; i++)
	{
		serviceitem[i] = new string[4];
	}




	std::string MainDomain;
	MainDomain = (LPSTR)SubKey;

	if (ERROR_SUCCESS == RegOpenKeyEx(Sheet, SubKey, 0, KEY_READ, &hKey)) {
		DWORD dwIndex = 0, NameSize, NameCnt, NameMaxLen, Type;
		DWORD KeySize, KeyCnt, KeyMaxLen, DateSize, MaxDateLen;
		if (ERROR_SUCCESS == RegQueryInfoKey(hKey, NULL, NULL, 0, &KeyCnt, &KeyMaxLen, NULL, &NameCnt, &NameMaxLen, &MaxDateLen, NULL, NULL)) {
			//cout << "共有" << KeyCnt << "个子键" << endl;
			for (DWORD dwIndex = 0; dwIndex < KeyCnt; dwIndex++)//枚举子键
			{
				std::string SubDomain;
				LPCTSTR Key;
				KeySize = KeyMaxLen + 1;//因为RegQueryInfoKey得到的长度不包括0结束字符，所以应加1
				char* szKeyName = (char*)malloc(KeySize);
				RegEnumKeyEx(hKey, dwIndex, szKeyName, &KeySize, NULL, NULL, NULL, NULL);//枚举子键
				SubDomain = szKeyName;
				Key = stringToLPCTSTR(MainDomain + "\\" + SubDomain);

				if (autoStartService(szKeyName, Key, sum) == 1) {
					sum++;
				}
				delete[] szKeyName;

			}
			return;
		}
	}
	else {
		cout << "Failed to open the form！" << endl;
	}
	RegCloseKey(hKey);//关闭句柄
	return;

}

void enumDriver(LPCTSTR SubKey, HKEY Sheet)
{
	HKEY hKey;
	HKEY hKey1;
	DWORD dwType = REG_SZ;
	DWORD dwLen = MAX_PATH;
	wchar_t data[MAX_PATH];
	int sum = 0;

	std::string MainDomain;
	MainDomain = (LPSTR)SubKey;

	if (ERROR_SUCCESS == RegOpenKeyEx(Sheet, SubKey, 0, KEY_READ, &hKey)) {
		DWORD dwIndex = 0, NameSize, NameCnt, NameMaxLen, Type;
		DWORD KeySize, KeyCnt, KeyMaxLen, DateSize, MaxDateLen;
		if (ERROR_SUCCESS == RegQueryInfoKey(hKey, NULL, NULL, 0, &KeyCnt, &KeyMaxLen, NULL, &NameCnt, &NameMaxLen, &MaxDateLen, NULL, NULL)) {
			//cout << "共有" << KeyCnt << "个子键" << endl;
			for (DWORD dwIndex = 0; dwIndex < KeyCnt; dwIndex++)//枚举子键
			{
				std::string SubDomain;
				LPCTSTR Key;
				KeySize = KeyMaxLen + 1;//因为RegQueryInfoKey得到的长度不包括0结束字符，所以应加1
				char* szKeyName = (char*)malloc(KeySize);
				RegEnumKeyEx(hKey, dwIndex, szKeyName, &KeySize, NULL, NULL, NULL, NULL);//枚举子键
				SubDomain = szKeyName;
				Key = stringToLPCTSTR(MainDomain + "\\" + SubDomain);

				if (autoStartDriver(szKeyName, Key) == 1) {
					sum++;
				}
				delete[] szKeyName;

			}
			return;
		}
	}
	else {
		cout << "Failed to open the form！" << endl;
	}
	RegCloseKey(hKey);//关闭句柄
	return;

}

void enumSchedule(std::string fileFolderPath)
{

	//所有job数据
	std::cout << "Scheduled Tasks" << '\n' << std::endl;
	std::vector<std::string> tiff_files;
	std::string fileExtension = "";
	get_files(fileFolderPath, fileExtension, tiff_files);

	for (int i = 0; i < tiff_files.size(); i++)
	{
		std::string ImagePath, company, description, Name;
		//std::cout << tiff_files[i] << std::endl;
		const char* taskFile = tiff_files[i].c_str();
		ImagePath = Cutstring2(GetTaskPath(taskFile));
		BaseFlow::Attribute::GetCompanyName(ImagePath, company);
		BaseFlow::Attribute::GetFileDescription(ImagePath, description);
		BaseFlow::Attribute::GetProductName(ImagePath, Name);
		std::cout << "Entry:" << Name << std::endl;
		std::cout << "ImagePath:" << ImagePath << std::endl;
		std::cout << "company:" << company << std::endl;
		std::cout << "description:" << description << std::endl;
		std::cout << "\n" << std::endl;
	}

	return;
}

void enumDDL(LPCTSTR SubKey, HKEY Sheet)
{

	HKEY hKey;

	if (RegOpenKeyEx(Sheet, SubKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		return;
	}
#define NAME_LEN 256
	char szValueName[NAME_LEN];
	BYTE szPortName[NAME_LEN];
	LONG status;
	DWORD dwIndex = 0;
	DWORD dwSizeValueName = 256;
	DWORD dwSizeofPortName = 256;
	DWORD Type;
	dwSizeValueName = NAME_LEN;
	dwSizeofPortName = NAME_LEN;
	std::string  Company;
	std::string  Description;
	do
	{
		status = RegEnumValue(hKey, dwIndex++, szValueName, &dwSizeValueName, NULL, &Type, szPortName, &dwSizeofPortName);
		if ((status == ERROR_SUCCESS))
		{
			printf("Entry = %s \n", szValueName);
			char* p = new char[sizeof(szPortName)];
			memcpy(p, szPortName, sizeof(szPortName));
			p[sizeof(szPortName)] = 0;
			cout << "Image Path = " << Cutstring2(Cutstring1(p)) << endl;
			BaseFlow::Attribute::GetCompanyName(Cutstring2(Cutstring1(p)), Company);
			BaseFlow::Attribute::GetFileDescription(Cutstring2(Cutstring1(p)), Description);
			cout << "Company = " << Company << endl;
			cout << "Description = " << Description << endl;
			printf("\n");
		}
		//每读取一次dwSizeValueName和dwSizeofPortName都会被修改
		//注意一定要重置,否则会出现很离奇的错误,出现读不了COM大于10以上的串口
		dwSizeValueName = NAME_LEN;
		dwSizeofPortName = NAME_LEN;
	} while ((status != ERROR_NO_MORE_ITEMS));
	RegCloseKey(hKey);
}



map<char*, char*> dic;

int StrReplace(char strRes[], char from[], char to[])
{
	int flag = 0;
	char* Ptr = NULL;
	char* middle_flag = strstr(strRes, from);
	if (middle_flag == NULL)
	{
		return flag;
	}

	int len = strlen(middle_flag);
	Ptr = (char*)malloc(len * sizeof(char));
	if (NULL == Ptr)
	{
		return flag;
	}
	strcpy(Ptr, middle_flag + (strlen(from)));
	if (middle_flag != NULL)
	{
		/* code */
		*middle_flag = '\0';
		strcat(strRes, to);
		strcat(strRes, Ptr);
		//free(Ptr);
		flag = 1;
	}
	return flag;
}
void format(char* path) {
	char pathvar[100];
	char tmp[100];
	sprintf(pathvar, "%s", getenv("windir"));
	sprintf(tmp, "%s", "%windir%");
	StrReplace(path, tmp, pathvar);
	sprintf(tmp, "%s", "%SystemRoot%");
	StrReplace(path, tmp, pathvar);
	sprintf(pathvar, "%s", "C:\\Users\\DELL\\AppData\\Local");
	sprintf(tmp, "%s", "%localappdata%");
	StrReplace(path, tmp, pathvar);
	sprintf(pathvar, "%s", "C:\\Program Files");
	sprintf(tmp, "%s", "%ProgramFiles%");
	StrReplace(path, tmp, pathvar);
}


BOOL InitialiseCOM() {
	HRESULT hResult;

	hResult = ::CoInitialize(NULL);
	if (!SUCCEEDED(hResult)) {
		//::wprintf(L"[>] [-] Error while initialising COM\n");
		return FALSE;
	}

	hResult = ::CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (!SUCCEEDED(hResult)) {
		//::wprintf(L"[-] Error while initialising COM security\n");
		return FALSE;
	}

	return TRUE;
}

BOOL CreateTaskServiceInstance(ITaskService*& pTaskService) {
	HRESULT hResult = ::CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pTaskService);
	if (!SUCCEEDED(hResult)) {
		//::wprintf(L"[-] Error while creating TaskService instance\n");
		return FALSE;
	}

	return TRUE;
}

BOOL ConnectToTaskService(ITaskService*& pTaskService) {
	VARIANT username;
	VARIANT password;
	VARIANT server;
	VARIANT domain;
	::VariantInit(&username);
	::VariantInit(&password);
	::VariantInit(&server);
	::VariantInit(&domain);

	HRESULT hResult = pTaskService->Connect(server, username, domain, password);
	if (!SUCCEEDED(hResult)) {
		//::wprintf(L"[-] Error while connecting to the TaskService\n");
		return FALSE;
	}

	::VariantClear(&username);
	::VariantClear(&password);
	::VariantClear(&server);
	::VariantClear(&domain);
	return TRUE;
}

BOOL GetRootTaskFolder(ITaskFolder*& pTaskFolder, ITaskService*& pTaskService, BSTR& bstrRootFolder) {
	HRESULT hResult = pTaskService->GetFolder(bstrRootFolder, &pTaskFolder);
	if (!SUCCEEDED(hResult)) {
		//::wprintf(L"[-] Error while getting the task root folder\n");
		return FALSE;
	}

	return TRUE;
}

//static string** taskitem;

BOOL EnumerateTasks(ITaskFolder*& pTaskFolder, DWORD indent) {
	HRESULT hResult, hResult1;

	/*
	taskitem=new string * [1024];
	for (int i = 0; i < 1024; i++)
	{
		taskitem[i] = new string[4];
	}*/

	// Get current folder name
	BSTR bstrFolderName = NULL;
	pTaskFolder->get_Name(&bstrFolderName);
	//wprintf_indent(bstrFolderName, indent, FALSE);

	// Get tasks in folder
	LONG lTasks = 0;
	IRegisteredTaskCollection* pTaskCollection = NULL;
	pTaskFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
	pTaskCollection->get_Count(&lTasks); //18个tasks
	int num = 0;
	// Loop through all tasks
	for (LONG i = 0; i < lTasks; i++) {
		IRegisteredTask* pTask = NULL;
		VARIANT item, actitem;
		::VariantInit(&item);
		item.vt = VT_I4;
		item.lVal = i + 1;
		hResult = pTaskCollection->get_Item(item, &pTask);
		if (SUCCEEDED(hResult)) {
			BSTR bstrTaskName = NULL;
			ITaskDefinition* taskdef = NULL;
			IActionCollection* ppact = NULL;
			IAction* pact = NULL;
			IExecAction* peact = NULL;
			BSTR bstrTaskimg = NULL;
			TASK_STATE pstate;
			//get name
			hResult = pTask->get_Path(&bstrTaskName);
			//get path
			pTask->get_Definition(&taskdef);
			taskdef->get_Actions(&ppact);
			ppact->get_Item(1, &pact);
			pact->QueryInterface(IID_IExecAction, (void**)&peact);
			//get state
			pTask->get_State(&pstate);
			//check state
			bool disabled = (pstate == TASK_STATE_DISABLED);
			bool queued = (pstate == TASK_STATE_QUEUED);
			bool ready = (pstate == TASK_STATE_READY);
			bool running = (pstate == TASK_STATE_RUNNING);
			bool unknown = (pstate == TASK_STATE_UNKNOWN);
			if (ready || running) {
				if (peact != NULL) {
					hResult1 = peact->get_Path(&bstrTaskimg);
					char* lpszText = _com_util::ConvertBSTRToString(bstrTaskimg);
					format(lpszText);
					bstrTaskimg = _com_util::ConvertStringToBSTR(lpszText);
					if (SUCCEEDED(hResult)) {
						//wprintf(bstrTaskName);
						//char* s =_com_util::ConvertBSTRToString(bstrTaskName) ;
						//taskitem[num][0] = s;
						//\Microsoft\Windows\AppID\PolicyConverter
						//wprintf(L"     ");
						if (bstrTaskimg != NULL) {
							//wprintf(bstrTaskimg);
							//char * s2=_com_util::ConvertBSTRToString(bstrTaskimg);
							//taskitem[num][1] = to_string(num);
							::dic.insert(std::pair<char*, char*>(_com_util::ConvertBSTRToString(bstrTaskName), _com_util::ConvertBSTRToString(bstrTaskimg)));
						}
						num++;
						//wprintf(L"\n");

					}
				}
				::SysFreeString(bstrTaskName);
			}
			else
				::SysFreeString(bstrTaskName);
		}
		else {
			//::wprintf(L"[-] Error while retriving task %d\n", i + 1);
		}
	}

	// Get all sub folders in current folder
	LONG lTaskFolders = 0;
	ITaskFolderCollection* pNewTaskFolderCollections = NULL;
	pTaskFolder->GetFolders(0, &pNewTaskFolderCollections);
	pNewTaskFolderCollections->get_Count(&lTaskFolders);

	// Loop through all the folders
	for (LONG i = 0; i < lTaskFolders; i++) {
		ITaskFolder* pNewTaskFolder = NULL;
		VARIANT item;
		::VariantInit(&item);
		item.vt = VT_I4;
		item.lVal = i + 1;

		pNewTaskFolderCollections->get_Item(item, &pNewTaskFolder);
		EnumerateTasks(pNewTaskFolder, indent + 3);
		pNewTaskFolder->Release();
	}

	pTaskCollection->Release();
	return TRUE;
}


void tasks()
{
	ITaskService* pTaskService = NULL;
	ITaskFolder* pTaskFolder = NULL;
	IRegisteredTaskCollection* pTaskCollection = NULL;
	BSTR bstrRootFolder = ::SysAllocString(L"\\");





	InitialiseCOM();
	CreateTaskServiceInstance(pTaskService);
	ConnectToTaskService(pTaskService);
	GetRootTaskFolder(pTaskFolder, pTaskService, bstrRootFolder);

	//::wprintf(L"[>] Parsing tasks ...\n");

	EnumerateTasks(pTaskFolder, 0);

	// Cleanup
	//::wprintf(L"\n[>] Cleaning everything ...\n");
	pTaskFolder->Release();
	pTaskService->Release();
	::SysFreeString(bstrRootFolder);
	::CoUninitialize();
	//::wprintf(L"[+] Cleaning everything ... OK\n\n");

	::dic.insert(std::pair<char*, char*>());
}