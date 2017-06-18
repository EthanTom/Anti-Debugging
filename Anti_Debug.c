/*
* Anti_Debug.c : Anti Debugging Library
* Written By : @Ice3man
* Email : Iceman12@protonmail.com
*
* This library of functions contain some anti-debugging
* functions which I've created. These have been collected
* from various sources and their number is increasing
* day by day.
*
* To Provide Maximum protection, obsfucate the blocks where
* these instructions are held and then decrypt them on
* runtime.
*
* (C) Sh4d0w-l0rd 2017 All Rights Reserved
*/

#include <windows.h>
#include <stdio.h>
#include "Anti_Debug.h"

void IsDebugger()
{
  // IsDebuggerPresent Method to Check Debugger
	if (IsDebuggerPresent()) {
		MessageBox(NULL, "The Process Is Being Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckRemoteDBG()
{
  int pbIsPresent;

  // Check Remote Debugger Method For Anti-Debugging
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &pbIsPresent);
	if (pbIsPresent == 1) {
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckOllyClass()
{
  HWND Hnd = FindWindow("OLLYDBG", 0);
	if (Hnd != NULL)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckProcessDebugPort()
{
  DWORD retVal;
  DWORD debugFlag;

  NTIP NtQueryInformationProcess;

  HANDLE hmod = LoadLibrary("ntdll.dll");
	NtQueryInformationProcess = (NTIP) GetProcAddress(hmod, "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), 0x07, &retVal, 4, 0);
	if (retVal != 0)
	 {
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
 		ExitProcess(0);
	 }
}

void CheckDebugFlag()
{
  // NT Query Debug Flag Method

  DWORD debugFlag;
  NTIP NtQueryInformationProcess;

  HANDLE hmod = LoadLibrary("ntdll.dll");
  NtQueryInformationProcess = (NTIP) GetProcAddress(hmod, "NtQueryInformationProcess");

	NtQueryInformationProcess(GetCurrentProcess(), 31, &debugFlag, 4, 0); // 31 is the enum for  DebugProcessFlags and = 0x1f in hex
	if (debugFlag == 0x00000000)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void DetachDebugger()
{
  NTST NtSetInformationThread;

  HANDLE hmod = LoadLibrary("ntdll.dll");
  NtSetInformationThread = (NTST) GetProcAddress(hmod, "NtSetInformationThread");
  NtSetInformationThread(GetCurrentThread(), 0x11, 0, 0);
}

void CheckDebugObject()
{
  PVOID hDebugObject;
  NTIP NtQueryInformationProcess;

  HANDLE hmod = LoadLibrary("ntdll.dll");
  NtQueryInformationProcess = (NTIP) GetProcAddress(hmod, "NtQueryInformationProcess");

  NtQueryInformationProcess(GetCurrentProcess(), 0x1e, &hDebugObject, 4, 0); // 0x1e is the enum for ProcessDebugObjectHandle
	if (hDebugObject)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}

	CloseHandle(hmod);
}

void OllyFormatVulnCheck()
{
  // Olly Debugger OutputFormatString Vuln
	__try {
		OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s")
						          TEXT("%s%s%s%s%s%s%s%s%s%s%s")
						          TEXT("%s%s%s%s%s%s%s%s%s%s%s")
						          TEXT("%s%s%s%s%s%s%s%s%s%s%s"));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckSeDebugCsr()
{
  CSR CsrGetProcessId;

  HANDLE hmod = LoadLibrary("ntdll.dll");
	CsrGetProcessId = GetProcAddress(hmod, (LPCSTR)"CsrGetProcessId");
	int pid = CsrGetProcessId();

	CloseHandle(hmod);

	HANDLE Csrss = 0;
	Csrss = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (Csrss != 0)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckCloseHandle()
{
	// Close Handle Error
	HANDLE Handle = (HANDLE)0x8000;
	__try
	{
		CloseHandle(Handle);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckNoDebugFlag()
{
	typedef void (WINAPI *pNtQueryInformationProcess) (HANDLE ,UINT ,PVOID ,ULONG , PULONG);

	DWORD NoDebugInherit = 0;
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll") ), "NtQueryInformationProcess" );
	NtQIP(GetCurrentProcess(), 0x1f, &NoDebugInherit, 4, NULL);
	if(NoDebugInherit == FALSE)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void ChecKVMStrReg()
{
	// Checking VMWare Using str Register
	unsigned char mem[4] = {0, 0, 0, 0};
	__asm str mem;
	if ((mem[0] == 0x00) && (mem[1] == 0x40))
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckRDTSCStepping()
{
	// RTDSC Debugger Detection
	int i = __rdtsc();
	int j = __rdtsc();
	if (j-i > 0xff)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckPerformanceStepping()
{
	LARGE_INTEGER li;
	LARGE_INTEGER li2;

	// Debugger Detection Using QueryPerformanceCounter
	QueryPerformanceCounter(&li);
	QueryPerformanceCounter(&li2);
	if ((li2.QuadPart-li.QuadPart) > 0xFF)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckTicksStepping()
{
	// Detecting By Single Stepping and GetTickCount
	int l = GetTickCount();
	int l2 = GetTickCount();
	if ((l2-l) > 0x10) {
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckIsDebuggerPEB()
{
	// IsDebuggerPresent Using PEB
	char IsDbgPresent = 0;
	__asm {
     		mov eax, fs:[30h]
        mov al, [eax + 2h]
        mov IsDbgPresent, al
	}

	if(IsDbgPresent)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckNTGlobalFlags()
{
	// Debugger Detection Using NT Global Flags
	unsigned long NtGlobalFlags = 0;
	__asm {
				mov eax, fs:[30h]
   	    mov eax, [eax + 68h]
        mov NtGlobalFlags, eax
	}

	if(NtGlobalFlags & 0x70)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

void CheckWinDBGClass()
{
	// Checking WinDBG
	HANDLE hWinDbg = FindWindow(TEXT("WinDbgFrameClass"), NULL);

	if(hWinDbg)
	{
		MessageBox(NULL, "The Software Cannot Run In a Debugger. Please Remove It.", "Debugger Detected", MB_OK | MB_ICONINFORMATION);
		ExitProcess(0);
	}
}

int CheckForCCBreakpoint(void* pMemory,  size_t SizeToCheck)
{
	// Function Not Mine. Creditz To Original Author
    unsigned char *pTmp = (unsigned char*)pMemory;
    unsigned char tmpchar = 0;

    for (size_t i = 0; i < SizeToCheck; i++)
     {
        tmpchar = pTmp[i];
        if( 0x99 == (tmpchar ^ 0x55) ) // 0xCC xor 0x55 = 0x99
            return TRUE;
     }

    return FALSE;
}
