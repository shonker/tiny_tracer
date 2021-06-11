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

scan_res ScanProcess(int pid, char out_dir[])
{
    std::string pesieve_path = std::string(PESIEVE_DIR) + "\\" + PE_SIEVE;

    HMODULE pesieve = LoadLibraryA(pesieve_path.c_str());
    if (!pesieve) {
        return SCAN_ERROR_0;
    }
    PEsieve_params args = { 0 };
    args.pid = pid;
    args.quiet = true;
    args.shellcode = true;
    args.no_hooks = false;
    args.json_lvl = pesieve::JSON_DETAILS;
    args.imprec_mode = pesieve::PE_IMPREC_AUTO;
    memcpy(args.output_dir, out_dir, strlen(out_dir));

    PEsieve_report(__cdecl *scan)(const PEsieve_params args) = 
        (PEsieve_report(__cdecl *)(const PEsieve_params args))GetProcAddress(pesieve, "PESieve_scan");
    if (!scan) {
        return SCAN_ERROR_1;
    }
    PEsieve_report report = scan(args);
    if (report.suspicious) {
        return SCAN_SUSPICIOUS;
    }
    return SCAN_NOT_SUSPICIOUS;
}
