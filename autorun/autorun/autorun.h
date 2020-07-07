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


LPTSTR GetCertificateDescription(PCCERT_CONTEXT pCertCtx)
{
	DWORD dwStrType;
	DWORD dwCount;
	LPTSTR szSubjectRDN = NULL;

	dwStrType = CERT_X500_NAME_STR;
	dwCount = CertGetNameString(pCertCtx,
		CERT_NAME_RDN_TYPE,
		0,
		&dwStrType,
		NULL,
		0);
	if (dwCount)
	{
		szSubjectRDN = (LPTSTR)LocalAlloc(0, dwCount * sizeof(TCHAR));
		CertGetNameString(pCertCtx,
			CERT_NAME_RDN_TYPE,
			0,
			&dwStrType,
			szSubjectRDN,
			dwCount);
	}

	return szSubjectRDN;
}

void splitstring(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
	std::string::size_type pos1, pos2;
	pos2 = s.find(c);
	pos1 = 0;
	while (std::string::npos != pos2)
	{
		v.push_back(s.substr(pos1, pos2 - pos1));

		pos1 = pos2 + c.size();
		pos2 = s.find(c, pos1);
	}
	if (pos1 != s.length())
		v.push_back(s.substr(pos1));
}


char* get_timestamp(LPCWSTR path)
{
	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO sWintrustFileInfo;
	WINTRUST_DATA      sWintrustData;
	HRESULT            hr;



	memset((void*)&sWintrustFileInfo, 0x00, sizeof(WINTRUST_FILE_INFO));
	memset((void*)&sWintrustData, 0x00, sizeof(WINTRUST_DATA));

	sWintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	sWintrustFileInfo.pcwszFilePath = path;
	sWintrustFileInfo.hFile = NULL;

	sWintrustData.cbStruct = sizeof(WINTRUST_DATA);
	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	sWintrustData.dwUnionChoice = WTD_CHOICE_FILE;
	sWintrustData.pFile = &sWintrustFileInfo;
	sWintrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	hr = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);

	if (TRUST_E_NOSIGNATURE == hr)
	{
		_tprintf(_T("No signature found on the file.\n"));
	}
	else if (TRUST_E_BAD_DIGEST == hr)
	{
		_tprintf(_T("The signature of the file is invalid\n"));
	}
	else if (TRUST_E_PROVIDER_UNKNOWN == hr)
	{
		_tprintf(_T("No trust provider on this machine can verify this type of files.\n"));
	}
	else if (S_OK != hr)
	{
		_tprintf(_T("WinVerifyTrust failed with error 0x%.8X\n"), hr);
	}
	else
	{
		_tprintf(_T("File signature is OK.\n"));

		// retreive the signer certificate and display its information
		CRYPT_PROVIDER_DATA const* psProvData = NULL;
		CRYPT_PROVIDER_SGNR* psProvSigner = NULL;
		CRYPT_PROVIDER_CERT* psProvCert = NULL;
		FILETIME                   localFt;
		SYSTEMTIME                 sysTime;

		psProvData = WTHelperProvDataFromStateData(sWintrustData.hWVTStateData);
		if (psProvData)
		{
			psProvSigner = WTHelperGetProvSignerFromChain((PCRYPT_PROVIDER_DATA)psProvData, 0, FALSE, 0);
			if (psProvSigner)
			{
				FileTimeToLocalFileTime(&psProvSigner->sftVerifyAsOf, &localFt);
				FileTimeToSystemTime(&localFt, &sysTime);
				_tprintf(_T("Signature Date = %.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n"), sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);

				psProvCert = WTHelperGetProvCertFromChain(psProvSigner, 0);
				if (psProvCert)
				{
					LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
					if (szCertDesc)
					{
						_tprintf(_T("File Signer = %s\n"), szCertDesc);
						//string CN = szCertDesc;
						//cout << CN;
						//vector<std::string> v;
						//splitstring(CN, v, "CN=");
						//cout << v[1];

						LocalFree(szCertDesc);
						/*if (v.size() == 2)
							return v[1];*/
					}
				}

				if (psProvSigner->csCounterSigners)
				{
					_tprintf(_T("\n"));
					// Timestamp information
					FileTimeToLocalFileTime(&psProvSigner->pasCounterSigners[0].sftVerifyAsOf, &localFt);
					FileTimeToSystemTime(&localFt, &sysTime);
					char  timesmp[1000];
					_tprintf(_T("Timestamp Date = %.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n"), sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
					sprintf(timesmp, ("%.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n"), sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
					cout << timesmp;
					return timesmp;
					psProvCert = WTHelperGetProvCertFromChain(&psProvSigner->pasCounterSigners[0], 0);
					if (psProvCert)
					{
						LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
						if (szCertDesc)
						{
							_tprintf(_T("Timestamp Signer = %s\n"), szCertDesc);
							LocalFree(szCertDesc);
						}
					}
				}
			}
		}
	}

	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);
}

string get_publisher(LPCWSTR path)
{
	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO sWintrustFileInfo;
	WINTRUST_DATA      sWintrustData;
	HRESULT            hr;



	memset((void*)&sWintrustFileInfo, 0x00, sizeof(WINTRUST_FILE_INFO));
	memset((void*)&sWintrustData, 0x00, sizeof(WINTRUST_DATA));

	sWintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	sWintrustFileInfo.pcwszFilePath = path;
	sWintrustFileInfo.hFile = NULL;

	sWintrustData.cbStruct = sizeof(WINTRUST_DATA);
	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	sWintrustData.dwUnionChoice = WTD_CHOICE_FILE;
	sWintrustData.pFile = &sWintrustFileInfo;
	sWintrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	hr = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);

	if (TRUST_E_NOSIGNATURE == hr)
	{
		_tprintf(_T("No signature found on the file.\n"));
	}
	else if (TRUST_E_BAD_DIGEST == hr)
	{
		_tprintf(_T("The signature of the file is invalid\n"));
	}
	else if (TRUST_E_PROVIDER_UNKNOWN == hr)
	{
		_tprintf(_T("No trust provider on this machine can verify this type of files.\n"));
	}
	else if (S_OK != hr)
	{
		_tprintf(_T("WinVerifyTrust failed with error 0x%.8X\n"), hr);
	}
	else
	{
		_tprintf(_T("File signature is OK.\n"));

		// retreive the signer certificate and display its information
		CRYPT_PROVIDER_DATA const* psProvData = NULL;
		CRYPT_PROVIDER_SGNR* psProvSigner = NULL;
		CRYPT_PROVIDER_CERT* psProvCert = NULL;
		FILETIME                   localFt;
		SYSTEMTIME                 sysTime;

		psProvData = WTHelperProvDataFromStateData(sWintrustData.hWVTStateData);
		if (psProvData)
		{
			psProvSigner = WTHelperGetProvSignerFromChain((PCRYPT_PROVIDER_DATA)psProvData, 0, FALSE, 0);
			if (psProvSigner)
			{
				FileTimeToLocalFileTime(&psProvSigner->sftVerifyAsOf, &localFt);
				FileTimeToSystemTime(&localFt, &sysTime);
				//_tprintf(_T("Signature Date = %.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n"), sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);

				psProvCert = WTHelperGetProvCertFromChain(psProvSigner, 0);
				if (psProvCert)
				{
					LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
					if (szCertDesc)
					{
						//_tprintf(_T("File Signer = %s\n"), szCertDesc);
						string CN = szCertDesc;
						//cout << CN;
						vector<std::string> v;
						splitstring(CN, v, "CN=");
						//cout << v[1];

						LocalFree(szCertDesc);
						if (v.size() == 2)
							return v[1];
					}
				}

				//if (psProvSigner->csCounterSigners)
				//{
				//	_tprintf(_T("\n"));
				//	// Timestamp information
				//	FileTimeToLocalFileTime(&psProvSigner->pasCounterSigners[0].sftVerifyAsOf, &localFt);
				//	FileTimeToSystemTime(&localFt, &sysTime);
				//	char  timesmp[1000];
				//	//_tprintf(_T("Timestamp Date = %.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n"), sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
				//	sprintf(timesmp, ("%.2d/%.2d/%.4d at %.2d:%2.d:%.2d\n"), sysTime.wDay, sysTime.wMonth, sysTime.wYear, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
				//	cout << timesmp;
				//	return timesmp;
				//	psProvCert = WTHelperGetProvCertFromChain(&psProvSigner->pasCounterSigners[0], 0);
				//	if (psProvCert)
				//	{
				//		LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
				//		if (szCertDesc)
				//		{
				//			_tprintf(_T("Timestamp Signer = %s\n"), szCertDesc);
				//			LocalFree(szCertDesc);
				//		}
				//	}
				//}
			}
		}
	}

	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);
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

VOID wprintf_indent(LPCWSTR string, DWORD indent, BOOL bIsTaskName) {
	BSTR bstrString = ::SysAllocString(string);
	for (DWORD i = 0; i < indent; i++) {
		::wprintf(L" ");
	}
	if (bIsTaskName) {
		::wprintf(L"- ");
	}
	else {
		::wprintf(L"+ ");
	}
	::wprintf(L"%s\n", string);
	::SysFreeString(bstrString);
}

BOOL IsAdministrator() {
	BOOL bSuccess = FALSE;
	HANDLE hProcessToken = NULL;

	bSuccess = ::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hProcessToken);
	if (bSuccess) {
		TOKEN_ELEVATION bIsElevated;
		DWORD dwSize = sizeof(bIsElevated);

		bSuccess = GetTokenInformation(hProcessToken, TokenElevation, &bIsElevated, dwSize, &dwSize);
		bSuccess = bIsElevated.TokenIsElevated;
	}

	if (hProcessToken) {
		::CloseHandle(hProcessToken);
	}

	return bSuccess;
}

BOOL InitialiseCOM() {
	HRESULT hResult;

	hResult = ::CoInitialize(NULL);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[>] [-] Error while initialising COM\n");
		return FALSE;
	}

	hResult = ::CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[-] Error while initialising COM security\n");
		return FALSE;
	}

	return TRUE;
}

BOOL CreateTaskServiceInstance(ITaskService*& pTaskService) {
	HRESULT hResult = ::CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pTaskService);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[-] Error while creating TaskService instance\n");
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
		::wprintf(L"[-] Error while connecting to the TaskService\n");
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
		::wprintf(L"[-] Error while getting the task root folder\n");
		return FALSE;
	}

	return TRUE;
}

BOOL EnumerateTasks(ITaskFolder*& pTaskFolder, DWORD indent) {
	HRESULT hResult, hResult1;

	// Get current folder name
	BSTR bstrFolderName = NULL;
	pTaskFolder->get_Name(&bstrFolderName);
	//wprintf_indent(bstrFolderName, indent, FALSE);

	// Get tasks in folder
	LONG lTasks = 0;
	IRegisteredTaskCollection* pTaskCollection = NULL;
	pTaskFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
	pTaskCollection->get_Count(&lTasks); //18个tasks

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
						wprintf(bstrTaskName);
						//\Microsoft\Windows\AppID\PolicyConverter
						wprintf(L"     ");
						if (bstrTaskimg != NULL) {
							wprintf(bstrTaskimg);
							::dic.insert(std::pair<char*, char*>(_com_util::ConvertBSTRToString(bstrTaskName), _com_util::ConvertBSTRToString(bstrTaskimg)));
						}
						wprintf(L"\n");
					}
				}
				::SysFreeString(bstrTaskName);
			}
			else
				::SysFreeString(bstrTaskName);
		}
		else {
			::wprintf(L"[-] Error while retriving task %d\n", i + 1);
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

