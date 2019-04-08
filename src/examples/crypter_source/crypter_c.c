

void mainf();

void init() {
	mainf();
	__asm__("nop"); 
}

void decryptMemory(void* (__stdcall *VirtualProtect)(void*,int,int,int*),unsigned char* section,int size){
	int buffer = 0;
	if(size > 0) {
		VirtualProtect(section,size,0x0040,&buffer);
		//Decrypt
		int in = 0;
		int xor = 0;
		for(unsigned char* i=section;i<section+size;i++) {
			xor = ((((in&0xF0)*(in&0x0F))&0xFF)+0x37)-0x13;
			*(i) = *(i)^(xor&0xFF);
			in++;
		}
	}
}

void mainf() {
	void* (__stdcall *VirtualProtect)(void*,int,int,int*) = *((void**)0xCCCCCCCC);

	
	decryptMemory(VirtualProtect,(unsigned char*)0xBBBBBBBB,0xAAAAAAAA);
	decryptMemory(VirtualProtect,(unsigned char*)0xBBBBBBBB,0xAAAAAAAA);
	decryptMemory(VirtualProtect,(unsigned char*)0xDDDDDDDD,0xCCCCCCCC);
	
	void* (__stdcall *GetProcAddress)(void* , char*) = *((void**)0xBBBBBBBB);
	void* (__stdcall *LoadLibrary)(char*) = *((void**)0xAAAAAAAA);

	__asm__("nop;nop;nop;nop"); //marker for import reconstruction
	return;
}
