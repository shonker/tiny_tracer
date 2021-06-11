#include "ScanProcess.h"

#include "my_paths.h"
#include <pe_sieve_api.h>

#ifdef _WIN64
#define PE_SIEVE "pe-sieve64.dll"
#else
#define PE_SIEVE "pe-sieve32.dll"
#endif

int getPidByThreadHndl(void* hndl)
{
    HANDLE phndl = (HANDLE) hndl;
    DWORD pid = GetProcessIdOfThread(phndl);
    return pid;
}

int getPidByProcessHndl(void *hndl)
{
    HANDLE phndl = (HANDLE)hndl;
    DWORD pid = GetProcessId(phndl);
    return pid;
}

bool ScanProcess(int pid)
{
    HMODULE process = LoadLibraryA(PE_SIEVE);

    PEsieve_params args = { 0 };
    args.pid = pid;
    args.quiet = true;
    args.shellcode = true;
    char out_dir[] = "C:\\scans\\";
    memcpy(args.output_dir, out_dir, strlen(out_dir));

    PEsieve_report(__cdecl *scan)(const PEsieve_params args) = 
        (PEsieve_report(__cdecl *)(const PEsieve_params args))GetProcAddress(process, "PESieve_scan");
    if (!scan) return false;

    PEsieve_report report = scan(args);
    if (report.suspicious) {
        return true;
    }
    return false;
}
