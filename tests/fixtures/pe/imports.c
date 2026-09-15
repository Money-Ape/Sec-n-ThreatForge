#include <windows.h>

int main(void)
{
    HANDLE process = GetCurrentProcess();

    if (process != NULL)
    {
        DWORD process_id = GetCurrentProcessId();

        if (process_id != 0)
        {
            Sleep(1);
        }

        CloseHandle(process);
    }

    return 0;
}
