#include <iostream>

#include "autorun.h"

LPCWSTR char_to_lpcwstr(char* input)
{
	WCHAR trans[256];
	memset(trans, 0, sizeof(trans));
	MultiByteToWideChar(CP_ACP, 0, input , strlen(input) + 1, trans, sizeof(trans) / sizeof(trans[0]));
	return trans;
}



void logon()
{
	HKEY rootkey1 = HKEY_LOCAL_MACHINE;
	HKEY rootkey2 = HKEY_CURRENT_USER ;

	LPCSTR keydata1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	LPCSTR keydata2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
	LPCSTR keydata3 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components";
	LPCSTR keydata4 = "Software\\Microsoft\\Windows\\CurrentVersionRunServicesOnce";
	LPCSTR keydata5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices";
	LPCSTR keydata6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx";
	
	map<char*, LPBYTE> mymap = read_value(rootkey1, keydata1);

	while (!mymap.empty())
	{	
		//string tmp_str = mymap.begin()->first;
		//std::cout << tmp_str << '\n';

		cout << mymap.begin()->first << '\t' << mymap.begin()->second<<endl;
		mymap.erase(mymap.begin());
	}
	mymap = read_value(rootkey1, keydata2);

	while (!mymap.empty())
	{
		//string tmp_str = mymap.begin()->first;
		//std::cout << tmp_str << '\n';

		cout << mymap.begin()->first << '\t' << mymap.begin()->second << endl;
		mymap.erase(mymap.begin());
	}

	mymap = read_value(rootkey2, keydata1);
	while (!mymap.empty())
	{
		//string tmp_str = mymap.begin()->first;
		//std::cout << tmp_str << '\n';

		cout << mymap.begin()->first << '\t' << mymap.begin()->second << endl;
		mymap.erase(mymap.begin());
	}

	mymap = read_value(rootkey2, keydata2);
	while (!mymap.empty())
	{
		//string tmp_str = mymap.begin()->first;
		//std::cout << tmp_str << '\n';

		cout << mymap.begin()->first << '\t' << mymap.begin()->second << endl;
		mymap.erase(mymap.begin());
	}




}

void service()
{
	HKEY rootkey = HKEY_LOCAL_MACHINE;
	LPCSTR keydata = "SYSTEM\\CurrentControlSet\\Services";

	map<int, char*> subitem;
	map<char*, LPBYTE> value;

	subitem = read_subitem(rootkey, keydata);
	string item;
	string tmpdata;
	DWORD type;

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
			description = read_description(rootkey,test);
			imagepath = read_imagepath(rootkey, test);
			cout << item << '\t' << description << '\t' << imagepath << endl;
		}
	}

}

void driver()
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
			//cout << type << endl;
			//objectname = read_objectname(rootkey, test);
			description = read_description(rootkey, test);
			imagepath = read_imagepath(rootkey, test);
			len = len+1 ;

			cout <<item << '\t'<<description<<'\t' << imagepath  << endl;
		}
	}
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

	::wprintf(L"[>] Parsing tasks ...\n");

	EnumerateTasks(pTaskFolder, 0);

	// Cleanup
	::wprintf(L"\n[>] Cleaning everything ...\n");
	pTaskFolder->Release();
	pTaskService->Release();
	::SysFreeString(bstrRootFolder);
	::CoUninitialize();
	::wprintf(L"[+] Cleaning everything ... OK\n\n");

	::dic.insert(std::pair<char*, char*>());
}

void ddls()
{
	HKEY rootkey = HKEY_LOCAL_MACHINE;
	LPCSTR keydata = "System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls";
	map<char*, LPBYTE> mymap = read_value(rootkey, keydata);

	string tmpdata;
	
	for (map<char*, LPBYTE>::iterator it = mymap.begin(); it != mymap.end(); ++it)
	{
		cout << it->first << "\t" << it->second << endl;
	}
}

void IE_BHO()
{
	HKEY rootkey = HKEY_LOCAL_MACHINE;
	LPCSTR keydata = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects";
	map<int, char*> subitem;
	map<char*, LPBYTE> value;

	subitem = read_subitem(rootkey, keydata);
	string item;
	string tmpdata;
	DWORD type;
	int len = 0;
	for (map<int, char*>::iterator it = subitem.begin(); it != subitem.end(); ++it)
	{
		//cout << it->first << "->" << it->second << endl;
		item = it->second;
		tmpdata = "SYSTEM\\CurrentControlSet\\Services\\" + item;
		
		LPCSTR test = tmpdata.c_str();
		cout << test << endl;
		value = read_value(rootkey,test);
		for (map<char*, LPBYTE>::iterator it = value.begin(); it != value.end(); ++it)
			cout << it->first << "->" << it->second << endl;
	}
}

int main(void)
{	
	//char* path = ("C:\\Program Files\\Notepad++\\notepad++.exe");
	//WCHAR trans[256];
	//memset(trans, 0, sizeof(trans));
	//MultiByteToWideChar(CP_ACP, 0, path, strlen(path) + 1, trans, sizeof(trans) / sizeof(trans[0]));
	////string com = get_info(trans);
	////string time = get_publisher(trans);
	////cout << time<<endl;
	//char* stmp = get_timestamp(trans);
	////cout << stmp << endl;

	while (1)
	{
		int option=-1;
		char quit;
		cout << "please choose the mode number"<<endl;
		cout << "1----Logon" << endl;
		cout << "2----Services" << endl;
		cout << "3----Drivers" << endl;
		cout << "4----Scheduled Tasks" << endl;
		cout << "5----DDLs" << endl;
		cout << "6----IE_BHO" << endl;

		cin >> option;

		switch (option)
		{
		case 1: 
			cout << "Logon :  Autorun entry ;   Image Path  ; Description  ;  Publisher  ;  TimeStamp :" << '\n'<<endl;
			logon();
			break;
		case 2: 
			cout << "Service :  Autorun entry ;  Description  ;  Image Path  ;  Publisher  ;  TimeStamp :" << '\n' << endl;
			service();
			break;
		case 3: 
			cout << "Driver :  Autorun entry ;  Description   ; Image Path  ;  Publisher  ;  TimeStamp :" << '\n' << endl;
			driver();
			break;
		case 4: 
			cout << "Tasks :  Autorun entry ;   Image Path  ; Description  ;  Publisher  ;  TimeStamp :" << '\n' << endl;
			tasks();
			break;
		case 5:
			cout << "DDLs :  Autorun entry ;   Image Path  ; Description  ;  Publisher  ;  TimeStamp :" << '\n' << endl;
			ddls();
			break;
		case 6:
			cout << "IE-BHO :  Autorun entry ;   Image Path  ; Description  ;  Publisher  ;  TimeStamp :" << '\n' << endl;
			IE_BHO();
			break;
		}

		cout << "quit?" << endl;
		cin >> quit;

		if (quit == 'q')
			break;
		else
			continue;
	}


	system("pause");
	return 0;
}

