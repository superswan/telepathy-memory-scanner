#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

int main(int argc, char *argv[])
{
    
    long MaxAddress = 0x7FFFFFFF;
    unsigned char *address = 0;

    if(argc==1)
      printf("***Error*** Usage: memscan <pid>\n");
    if(argc>=2)
    {

    char *p = argv[1];
    int pid = atoi(p);

    DWORD access = PROCESS_VM_READ |
                   PROCESS_QUERY_INFORMATION |
                   PROCESS_VM_WRITE |
                   PROCESS_VM_OPERATION;
    HANDLE hProc = OpenProcess(
      access,
      FALSE,
      pid 
    );
  printf("[!] Opened handle to process: %d\n", pid);

  while(address <= MaxAddress) 
  {
      MEMORY_BASIC_INFORMATION m;
      int result = VirtualQueryEx(hProc, address, &m, sizeof(m));
      printf("0x%08x,\t0x%08x,\t%d,\t%d\n", address, (unsigned char*)m.BaseAddress, result, m.RegionSize);
      if (address == (unsigned char*)m.BaseAddress + m.RegionSize)
          break;
      address =(unsigned char*)m.BaseAddress + m.RegionSize;
  };

  CloseHandle(hProc);
  }
  return 0;
}




