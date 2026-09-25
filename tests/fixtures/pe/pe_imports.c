#include <windows.h>

int main(void){
	HANDLE handle = GetCurrentProcess();

	if (handle != NULL){
		CloseHandle(handle);
	}
	return 0;
}
