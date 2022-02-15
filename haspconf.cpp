//NVD Sentinel license manager configuration utility
//Copyright © 2019-2022, Nikolay Dudkin

//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.
//You should have received a copy of the GNU General Public License
//along with this program.If not, see<https://www.gnu.org/licenses/>.

#define UNICODE

#define NTDDI_VERSION 0x06000000
#define _WIN32_IE 0x0700

#include <windows.h>
#include <wctype.h>
#include <stdio.h>
#include <shlobj.h>
#include <shlwapi.h>

#include "lib\cmdline.hpp"

CmdLine *cl = NULL;

wchar_t *tmplt = L"[SERVER]\r\nname = %s\r\nidle_session_timeout_mins = 720\r\npagerefresh = 3\r\nlinesperpage = 20\r\nACCremote = 0\r\nenablehaspc2v = 0\r\nold_files_delete_days = 90\r\n\r\nenabledetach = 0\r\nreservedseats = 0\r\nreservedpercent = 0\r\ndetachmaxdays = 14\r\ncommuter_delete_days = 7\r\ndisable_um = 0\r\n\r\nrequestlog = 0\r\nloglocal = 0\r\nlogremote = 0\r\nlogadmin = 0\r\nerrorlog = 0\r\nrotatelogs = 0\r\naccess_log_maxsize = 0 ;kB\r\nerror_log_maxsize = 0 ;kB\r\nzip_logs_days = 0\r\ndelete_logs_days = 0\r\npidfile = 0\r\npassacc = 0\r\n\r\naccessfromremote = 1\r\naccesstoremote = 1\r\nbind_local_only = 0  ; 0=all adapters, 1=localhost only\r\n\r\nproxyconnect = 0  ; 0=disabled, 1=WPAD, 2=manual\r\nproxyhost = \r\nproxyport = 3128\r\n\r\n\r\n[UPDATE]\r\ndownload_url = sentinelcustomer.gemalto.com/Sentinel/LanguagePacks/\r\nupdate_host = www3.safenet-inc.com\r\nlanguage_url = /hasp/language_packs/end-user/\r\n\r\n\r\n[REMOTE]\r\nbroadcastsearch = %d\r\naggressive = %d\r\nserversearchinterval = 30\r\n%s\r\n\r\n\r\n[ACCESS]\r\n\r\n\r\n[USERS]\r\n\r\n\r\n[VENDORS]\r\n\r\n\r\n[EMS]\r\nemsurl = http://localhost:8080\r\nemsurl = http://127.0.0.1:8080\r\n\r\n\r\n[LOGPARAMETERS]\r\ntext = {timestamp} {clientaddr}:{clientport} {clientid} {method} {url} {function}({functionparams}) result({statuscode}){newline}\r\n\r\n\0";

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

void die(wchar_t * location, int error)
{
	wchar_t buf[256];
	memset(buf, 0, sizeof(wchar_t) * 256);
	swprintf(buf, 255, L"Error %d at %s", error, location);

	wprintf(buf);
	fflush(stdout);

	if(cl)
		delete cl;

	ExitProcess(error);
}

BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(L"kernel32"), "IsWow64Process");
	if(fnIsWow64Process != NULL)
	{
		fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
	}

	return bIsWow64;
}

void RestartService()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	SERVICE_STATUS_PROCESS ssStatus; 
	DWORD dwBytesNeeded;

	SERVICE_STATUS lpServiceStatus;

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!schSCManager) 
		die(L"OpenSCManager", 10);

	schService = OpenService(schSCManager, L"hasplms", SERVICE_ALL_ACCESS);
	if (!schService)
	{
		CloseServiceHandle(schSCManager);
		die(L"OpenService", 11); 
	}

	if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE) &ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
	{
		CloseServiceHandle(schService); 
		CloseServiceHandle(schSCManager);
		die(L"QueryServiceStatusEx", 12);
	}

	if(ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
	{
		if(!ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) &lpServiceStatus))
		{
			CloseServiceHandle(schService); 
			CloseServiceHandle(schSCManager);
			die(L"ControlService", 13);
		}
	}

	int count = 0;

	while (ssStatus.dwCurrentState != SERVICE_STOPPED)
	{
		if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE) &ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
		{
			CloseServiceHandle(schService); 
			CloseServiceHandle(schSCManager);
			die(L"QueryServiceStatusEx", 14);
		}

		Sleep(500);
		if(count++ > 20)
		{
			CloseServiceHandle(schService); 
			CloseServiceHandle(schSCManager);
			die(L"Timeout waiting for service to stop", 15);
		}
	}

	if (!StartService(schService, 0, NULL))
	{
		CloseServiceHandle(schService); 
		CloseServiceHandle(schSCManager);
		die(L"StartService", 16);
	}

	CloseServiceHandle(schService); 
	CloseServiceHandle(schSCManager);
}

int wmain()
{
	cl = new CmdLine(GetCommandLine());

	wchar_t *servers = cl->GetOptionValue(L"-servers", 1, 1);

	if(cl->HasParam(L"-?", 0) || !servers)
	{
		wprintf(L"HaspConf 1.1\r\n(c) 2019-2022, Nikolay Dudkin\r\n\r\nUsage: %s [-?] -servers:\"comma-separated list of server names\" [-broadcast:0|1] [-aggressive:0|1]", cl->GetCommand(0)->GetName(0));
		delete cl;
		return 0;
	}

	int serveraddrs_l = 1;
	wchar_t *p1 = servers;
	do
	{
		if(*p1 == L' ' || *p1 == L',')
			serveraddrs_l++;
	} while(*p1++);
	serveraddrs_l = serveraddrs_l * wcslen(L"serveraddr = XX") + wcslen(servers) - serveraddrs_l + 2; //why do I only do this...

	wchar_t *serveraddrs = new wchar_t[serveraddrs_l];
	memset(serveraddrs, 0, sizeof(wchar_t) * serveraddrs_l);

	wchar_t *delims = L" ,";
	wchar_t *p2 = NULL;
	p1 = wcstok(servers, delims, &p2); 

	while(p1)
	{ 
		wcsncat(serveraddrs, L"serveraddr = ", max(serveraddrs_l - wcslen(serveraddrs) - 1, 0)); //missing _s functions...
		wcsncat(serveraddrs, p1, max(serveraddrs_l - wcslen(serveraddrs) - 1, 0));
		wcsncat(serveraddrs, L"\r\n", max(serveraddrs_l - wcslen(serveraddrs) - 1, 0));
		p1 = wcstok(NULL, delims, &p2); 
	}

	int broadcast = 0;
	int aggressive = 0;

	p1 = cl->GetOptionValue(L"-broadcast", 1, 1);
	broadcast = p1 && !wcscmp(p1, L"1");

	p1 = cl->GetOptionValue(L"-aggressive", 1, 1);
	aggressive = p1 && !wcscmp(p1, L"1");

	DWORD computername_l = 256;
	wchar_t *computername = new wchar_t[computername_l];
	memset(computername, 0, sizeof(wchar_t) * computername_l);

	if(!GetComputerName(computername, &computername_l))
	{
		if(GetLastError() == ERROR_BUFFER_OVERFLOW)
		{
			delete []computername;
			computername = new wchar_t[computername_l];
			memset(computername, 0, sizeof(wchar_t) * computername_l);

			if(!GetComputerName(computername, &computername_l))
			{
				delete []computername;
				delete []serveraddrs;
				die(L"GetComputerName", 1);
			}
		}
		else
		{
			delete []computername;
			delete []serveraddrs;
			die(L"GetComputerName", 2);
		}
	}

	int buf_l = wcslen(tmplt) + wcslen(serveraddrs) + computername_l - 5; //oops I did it again...
	wchar_t *buf_w = new wchar_t[buf_l];
	memset(buf_w, 0, sizeof(wchar_t) * buf_l);

	if(swprintf(buf_w, buf_l, tmplt, computername, broadcast, aggressive, serveraddrs) < 0)
	{
		delete []buf_w;
		delete []computername;
		delete []serveraddrs;
		die(L"swprintf", 3);
	}

	delete []computername;
	delete []serveraddrs;

	char *buf_c = new char[buf_l];
	memset(buf_c, 0, sizeof(char) * buf_l);

	if(!WideCharToMultiByte(CP_ACP, 0, buf_w, wcslen(buf_w), buf_c, wcslen(buf_w), NULL, NULL))
	{
		delete []buf_w;
		delete []buf_c;
		die(L"WideCharToMultiByte", 4);
	}

	delete []buf_w;

	wchar_t *kf;

	if(IsWow64())
	{
		if(SHGetKnownFolderPath(FOLDERID_ProgramFilesCommon, 0, 0, &kf) != S_OK)
		{
			delete []buf_c;
			die(L"SHGetKnownFolderPath", 5);
		}
	}
	else
	{
		if(SHGetKnownFolderPath(FOLDERID_ProgramFilesCommonX86, 0, 0, &kf) != S_OK)
		{
			delete []buf_c;
			die(L"SHGetKnownFolderPath", 6);
		}
	}

	wchar_t *path = new wchar_t[MAX_PATH + 1];
	memset(path, 0, sizeof(wchar_t) * (MAX_PATH + 1));

	swprintf(path, MAX_PATH, L"%s\\Aladdin Shared", kf);
	if(!PathFileExists(path))
		CreateDirectory(path, NULL);

	swprintf(path, MAX_PATH, L"%s\\Aladdin Shared\\HASP", kf);
	if(!PathFileExists(path))
		CreateDirectory(path, NULL);

	swprintf(path, MAX_PATH, L"%s\\Aladdin Shared\\HASP\\hasplm.ini", kf);

	CoTaskMemFree(kf);

	FILE *file = _wfopen(path, L"wb");
	if(!file)
	{
		delete []buf_c;
		delete []path;
		die(L"_wfopen", 7);
	}

	if(fwrite(buf_c, 1, strlen(buf_c), file) < strlen(buf_c))
	{
		delete []buf_c;
		delete []path;
		die(L"fwrite", 8);
	}

	fclose(file);

	delete []buf_c;
	delete []path;

	RestartService();

	delete cl;
	return 0;
}
