#include <Windows.h>
#include <kernel/driver.h>
#include <iostream>
#include <string>
kernel::driver driver;

int test()
{
	printf("Base addr again: 0x%p\n", driver.get_process_base());
	return 0;
}

int main()
{
	SetConsoleTitle("Usermode Driver Test");
	printf("Welcome to Usermode.\n");


	if (!driver.init())
	{
		printf("Initialization or communication test failed.\nPlease make sure driver is loaded.\n");
		Sleep(3500);
		return 1;
	}

	driver.init();
	driver.attach( GetCurrentProcessId( ) );

	std::cout << "kernel32.dll: " << driver.get_process_module("kernel32.dll") << std::endl;
	
	std::cout << "win32u.dll: " << driver.get_process_module("win32u.dll") << std::endl;
	std::cin.get( );

	printf("getting base...\n");
	uintptr_t base = driver.get_process_base(GetCurrentProcessId());
	printf("base: %p\n", base);
	
	uintptr_t varInt = 0x7FF6134F60D0 - 0x00007FF6134F0000 + base;
	uintptr_t arrChar128 = 0x7FF6134F6050 - 0x00007FF6134F0000 + base;
	uintptr_t memoryPtr = 0x7FF6134F6788 - 0x00007FF6134F0000 + base;
	
	
	printf("Testing bad write...\n");
	driver.write<int>(0x69, 0xDEADBEEF);
	printf("Bad write passed.\n");

	printf("Writing to varInt: (%i) -> 654321\n", driver.read<int>(varInt));
	driver.write<int>(varInt, 654321);
	
	char arrChar[128];
	driver.read_buffer(arrChar128, (uint8_t *)arrChar, sizeof(arrChar));
	printf("Writing to arrChar[128]: \"%s\" -> HeLlO\n", arrChar);
	
	memcpy(arrChar, "HeLlO\0\0\0\0\0\0\0\0", sizeof("HeLlO\0\0\0\0\0\0\0\0"));
	driver.write_buffer(arrChar128, (uint8_t *)arrChar, sizeof(arrChar));

	printf("INTERP = GOAT.\n");

	test();
	Sleep(9e9);
	//while (true)
	//{
	//	int thing = driver.read<int>(varInt);
	//	printf("%i\n", thing);
	//}
	
	std::cin.get();
	return 0;
}