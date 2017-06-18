/*
* Anti_Debug.h : This File Contains the
* function prototypes and Other Stuff for the Anti
* Debugging Functions.
*
* Coded By : @Ice3man
* (C) Sh4d0w-l0rd 2017 All Rights Reserved
* Please Give Creditz Wherever Due
*
* Email : Iceman12@protonmail.com
*/

typedef BOOL (__stdcall *NTIP) (HANDLE ,UINT ,PVOID ,ULONG , PULONG); // Process32Next
typedef BOOL (__stdcall *CSR) (void); //CSR Get Process ID
typedef BOOL (__stdcall *NTST) (HANDLE, int, int, int); // Nt Set Information

// Function Prototypes

int CheckForCCBreakpoint(void* ,  size_t); // Check For Int-3 return (0xCC) in a memory block
void IsDebugger(); // Uses IsDebuggerPresent API. Not So Good.
void CheckRemoteDBG(); // Uses CheckRemoteDebugger API Call.
void CheckOllyClass(); // Uses FindWindow to Find Olly
void CheckProcessDebugPort(); // Uses NT Query Information Process to Check Open Debug Port
void CheckDebugFlag(); // Uses NT Query Information process to Check Debug Flag
void DetachDebugger(); // Detaches the Current Active Debugger
void CheckDebugObject(); // Uses Same NTQuery method to check ProcessDebug Object
void OllyFormatVulnCheck(); // Checks for a flaw (format String) bug in Olly Debugger
void CheckSeDebugCsr(); // Checks For SeDebugFlag using Csrss.exe
void CheckCloseHandle(); //Checks For CloseHandle Bug
void CheckNoDebugFlag(); //Checks the value of NoDebugFlag Indicating a Debugger
void CheckVMStrReg(); // Checks For Virtual Machines Using str Register
void CheckRDTSCStepping(); // Checks For Single-Stepping through RDTSC Instruction
void CheckPerformanceStepping(); // Checks for Single-Stepping through Performance Counter
void CheckTicksStepping(); // Checks FOr Single-Stepping through Ticks Count
void CheckIsDebuggerPEB(); // Checks For Debugger Through PEB.
void CheckNTGlobalFlags(); // Checks For Debugger Using NTGlobal Flags.
void CheckWinDBGClass(); // Uses FindWindow to Find WinDBG
