#pragma once
#include <iostream>

int getPidByThreadHndl(void* hndl);
int getPidByProcessHndl(void *hndl);

bool ScanProcess(int pid);
