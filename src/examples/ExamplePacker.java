package examples;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import pusty.f0xpe.location.MemorySection;
import pusty.f0xpe.payload.EditablePayload;
import pusty.f0xpe.payload.ModifyPE;
import pusty.f0xpe.payload.Payload;
import pusty.f0xpe.payload.ModifyPE.EditableImportEntry;
import pusty.f0xpe.payload.ModifyPE.EditableImportTable;
import pusty.f0xpe.pe.DescriptorImport;
import pusty.f0xpe.pe.ExecutableReader;
import pusty.f0xpe.pe.IMAGE_OPTIONAL_HEADER32;
import pusty.f0xpe.pe.IMAGE_SECTION_HEADER;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_IMPORT_DESCRIPTOR;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_THUNK_DATA;

/**
 * This is an advanced example showing the possibility, of using this library
 * for dynamic encryption and loading of binaries. (32bit example)
 */
public class ExamplePacker {

	public static void main(String[] args) throws Exception {
		
		//the file to encrypt
		File file = new File(args[0]);
		
		ExecutableReader reader = ExecutableReader.create(file);
		
		//Set the permissions for the sections to make them only readable
		for (int i = 0; i < reader.getSectionHeader().length; i++) {
			if ((reader.getSectionHeader()[i].getCharacteristics() & IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_EXECUTE) != 0) {
				reader.getSectionHeader()[i].setCharacteristics(
						IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_READ | IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_INITIALIZED_DATA);
			}
		}
		
		//Inject a new code and data section
		int code_section = ModifyPE.injectSection(reader, ".boot", 0x2024,
				IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_READ | IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_CODE
						| IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_EXECUTE);
		int data_section = ModifyPE.injectSection(reader, ".dboot", 0x2024,
				IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_READ | IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_INITIALIZED_DATA);
		
		
		//create a copy of the import table
		ArrayList<COPY_IMPORT> copy_import_list = parseTableValue(reader.getOptionalHeader().getImportDescriptor());
	
		//Create a new import table which only imports kernel32 with GetProcAddress, LoadLibraryA and VirtualProtect
		EditableImportTable table = new EditableImportTable();
		EditableImportEntry dll_0 = new EditableImportEntry("kernel32.dll");
		//dll_0.addOrdinal(584); // 584 "GetProcAddress"
		dll_0.addNamed("GetProcAddress");
		//dll_0.addOrdinal(830); // 830 "LoadLibraryA"
		dll_0.addNamed("LoadLibraryA");
		//dll_0.addOrdinal(1269); // 1269 "VirtualProtect"
		dll_0.addNamed("VirtualProtect");		
		table.getEntries().add(dll_0);
		
		//Delete the original import table
		ModifyPE.clearTable(reader);
		
		//Write the new import table into the binary
		int freeData = (table.writeTable(reader, reader.getSectionHeader()[data_section].getPointerToRawData(), false));
		int freeDataDelta = freeData - reader.getSectionHeader()[data_section].getPointerToRawData();
	
		int addressOfGetProcAddress = getOffsetOfTableValue(reader.getOptionalHeader().getImportDescriptor(),
				"kernel32.dll", "GetProcAddress", 0); // "GetProcAddress"
		addressOfGetProcAddress += reader.getOptionalHeader().getImageBase(); // need to add support for reloc
		int addressOfLoadLibrary = getOffsetOfTableValue(reader.getOptionalHeader().getImportDescriptor(),
				"kernel32.dll", "LoadLibraryA", 0); // "LoadLibraryA"
		addressOfLoadLibrary += reader.getOptionalHeader().getImageBase(); // need to add support for reloc
		int addressOfVirtualProtect = getOffsetOfTableValue(reader.getOptionalHeader().getImportDescriptor(),
				"kernel32.dll", "VirtualProtect", 0); // "VirtualProtect"
		addressOfVirtualProtect += reader.getOptionalHeader().getImageBase(); // need to add support for reloc

		int old_entry = reader.getOptionalHeader().getAddressOfEntryPoint();
		old_entry += reader.getOptionalHeader().getImageBase(); //TODO: need to add support for reloc
		reader.getOptionalHeader().setAddressOfEntryPoint(reader.getSectionHeader()[code_section].getVirtualAddress());
		
		EditablePayload crypter = new EditablePayload(ExamplePacker.class.getResourceAsStream("crypter_c.bin").readAllBytes());
		
		ModifyPE.inject(reader, crypter, new MemorySection(reader.getSectionHeader()[code_section]));
		ModifyPE.replaceInt(reader, crypter, new MemorySection(reader.getSectionHeader()[code_section]),
				0xCCCCCCCC, addressOfVirtualProtect);

		// XORING
		encryptSection(reader, ".text", crypter, code_section, 0xAAAAAAAA, 0xBBBBBBBB, 0);
		encryptSection(reader, ".rdata", crypter, code_section, 0xAAAAAAAA, 0xBBBBBBBB, 0);
		// XORING

		ModifyPE.replaceInt(reader, crypter, new MemorySection(reader.getSectionHeader()[code_section]),
				0xAAAAAAAA, addressOfLoadLibrary);
		ModifyPE.replaceInt(reader, crypter, new MemorySection(reader.getSectionHeader()[code_section]),
				0xBBBBBBBB, addressOfGetProcAddress);

		int writingOffset = ModifyPE.searchInt(reader, crypter,
				new MemorySection(reader.getSectionHeader()[code_section]), 0x90909090);
		reader.getStream().setIndex(freeData);

		for (COPY_IMPORT copy_import : copy_import_list) {
			// BB EE EE EE EE C7 04 24 CC CC CC CC 8B 45 F0 FF D0 83 EC 04 C7 44 24 04 DD DD
			// DD DD 89 04 24 8B 45 F4 FF D0 83 EC 08 89 03
			/*
			 * mov ebx, 0xeeeeeeee
			 * mov dword ptr [esp], 0xcccccccc
			 * mov eax, dword ptr [ebp -0x10]
			 * call eax
			 * sub esp, 4
			 * mov dword ptr [esp + 4], 0xdddddddd
			 * mov dword ptr [esp], eax
			 * mov eax, dword ptr [ebp - 0xc]
			 * call eax 
			 * sub esp, 8 
			 * mov dword ptr [ebx], eax
			 */
			int thunk_addr = copy_import.offset_thunk;
			thunk_addr += reader.getOptionalHeader().getImageBase(); // need to add support for reloc
			int dll_addr = reader.offset2rva(reader.getStream().getIndex()).getAddr32();
			dll_addr += reader.getOptionalHeader().getImageBase();// need to add support for reloc
			reader.getStream().writeString(copy_import.dll);
			int proc_addr = reader.offset2rva(reader.getStream().getIndex()).getAddr32();
			proc_addr += reader.getOptionalHeader().getImageBase();// need to add support for reloc
			if (copy_import.imp != null)
				reader.getStream().writeString(copy_import.imp);
			else
				proc_addr = copy_import.ordinal;

			reader.getStream().setByte(writingOffset + 0, (byte) 0xBB);
			reader.getStream().setByte(writingOffset + 1, (byte) (thunk_addr & 0xFF));
			reader.getStream().setByte(writingOffset + 2, (byte) ((thunk_addr >>> 8) & 0xFF));
			reader.getStream().setByte(writingOffset + 3, (byte) ((thunk_addr >>> 16) & 0xFF));
			reader.getStream().setByte(writingOffset + 4, (byte) ((thunk_addr >>> 24) & 0xFF));
			reader.getStream().setByte(writingOffset + 5, (byte) 0xC7);
			reader.getStream().setByte(writingOffset + 6, (byte) 0x04);
			reader.getStream().setByte(writingOffset + 7, (byte) 0x24);
			reader.getStream().setByte(writingOffset + 8, (byte) (dll_addr & 0xFF));
			reader.getStream().setByte(writingOffset + 9, (byte) ((dll_addr >>> 8) & 0xFF));
			reader.getStream().setByte(writingOffset + 10, (byte) ((dll_addr >>> 16) & 0xFF));
			reader.getStream().setByte(writingOffset + 11, (byte) ((dll_addr >>> 24) & 0xFF));
			reader.getStream().setByte(writingOffset + 12, (byte) 0x8B);
			reader.getStream().setByte(writingOffset + 13, (byte) 0x45);
			reader.getStream().setByte(writingOffset + 14, (byte) 0xEC);
			reader.getStream().setByte(writingOffset + 15, (byte) 0xFF);
			reader.getStream().setByte(writingOffset + 16, (byte) 0xD0);
			reader.getStream().setByte(writingOffset + 17, (byte) 0x83);
			reader.getStream().setByte(writingOffset + 18, (byte) 0xEC);
			reader.getStream().setByte(writingOffset + 19, (byte) 0x04);
			reader.getStream().setByte(writingOffset + 20, (byte) 0xC7);
			reader.getStream().setByte(writingOffset + 21, (byte) 0x44);
			reader.getStream().setByte(writingOffset + 22, (byte) 0x24);
			reader.getStream().setByte(writingOffset + 23, (byte) 0x04);
			reader.getStream().setByte(writingOffset + 24, (byte) (proc_addr & 0xFF));
			reader.getStream().setByte(writingOffset + 25, (byte) ((proc_addr >>> 8) & 0xFF));
			reader.getStream().setByte(writingOffset + 26, (byte) ((proc_addr >>> 16) & 0xFF));
			reader.getStream().setByte(writingOffset + 27, (byte) ((proc_addr >>> 24) & 0xFF));
			reader.getStream().setByte(writingOffset + 28, (byte) 0x89);
			reader.getStream().setByte(writingOffset + 29, (byte) 0x04);
			reader.getStream().setByte(writingOffset + 30, (byte) 0x24);
			reader.getStream().setByte(writingOffset + 31, (byte) 0x8B);
			reader.getStream().setByte(writingOffset + 32, (byte) 0x45);
			reader.getStream().setByte(writingOffset + 33, (byte) 0xF0);
			reader.getStream().setByte(writingOffset + 34, (byte) 0xFF);
			reader.getStream().setByte(writingOffset + 35, (byte) 0xD0);
			reader.getStream().setByte(writingOffset + 36, (byte) 0x83);
			reader.getStream().setByte(writingOffset + 37, (byte) 0xEC);
			reader.getStream().setByte(writingOffset + 38, (byte) 0x08);
			reader.getStream().setByte(writingOffset + 39, (byte) 0x89);
			reader.getStream().setByte(writingOffset + 40, (byte) 0x03);
			writingOffset += 41;

		}
		encryptSection(reader, ".dboot", crypter, code_section, 0xCCCCCCCC, 0xDDDDDDDD, freeDataDelta);

		reader.getStream().setByte(writingOffset + 0, (byte) 0x90);
		reader.getStream().setByte(writingOffset + 1, (byte) 0xC9);
		reader.getStream().setByte(writingOffset + 2, (byte) 0xC3);

		// 0x60, 0x89, 0xE5, 0xE8, 0x6A, 0x00, 0x00, 0x00, 0x61, 0x68, 0xAA, 0xAA, 0xAA,
		// 0xAA, 0xC3
		/*
		 * pushal
		 * mov ebp, esp
         * call 0x72
         * popal
		 * push 0xaaaaaaaa
         * ret
		 */
		writingOffset = reader.getSectionHeader()[code_section].getPointerToRawData();
		reader.getStream().setByte(writingOffset + 0, (byte) 0x60);
		reader.getStream().setByte(writingOffset + 1, (byte) 0x89);
		reader.getStream().setByte(writingOffset + 2, (byte) 0xE5);
		reader.getStream().setByte(writingOffset + 3, (byte) 0xE8);
		reader.getStream().setByte(writingOffset + 4, (byte) 0x9C); // this needs adjusting after changing decrypting
																	// code
		reader.getStream().setByte(writingOffset + 5, (byte) 0x00); // this needs adjusting after changing decrypting
																	// code
		reader.getStream().setByte(writingOffset + 6, (byte) 0x00);
		reader.getStream().setByte(writingOffset + 7, (byte) 0x00);
		reader.getStream().setByte(writingOffset + 8, (byte) 0x61);
		reader.getStream().setByte(writingOffset + 9, (byte) 0x68);
		reader.getStream().setByte(writingOffset + 10, (byte) (old_entry & 0xFF));
		reader.getStream().setByte(writingOffset + 11, (byte) ((old_entry >>> 8) & 0xFF));
		reader.getStream().setByte(writingOffset + 12, (byte) ((old_entry >>> 16) & 0xFF));
		reader.getStream().setByte(writingOffset + 13, (byte) ((old_entry >>> 24) & 0xFF));
		reader.getStream().setByte(writingOffset + 14, (byte) 0xC3);

		// purge reloc
		reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_BASERELOC]
				.setVirtualAddresss(0);
		// reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_BASERELOC].setSize(0);
		// purge debug
		reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_DEBUG]
				.setVirtualAddresss(0);
		reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_DEBUG].setSize(0);

		// reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].setVirtualAddresss(0);
		// reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].setSize(0);

		//purge section names
		for (int i = 0; i < reader.getSectionHeader().length; i++)
			reader.getSectionHeader()[i].setName("");

		int start_memory = reader.getSectionHeader()[reader.getSectionHeader().length - 1].getPointerToRawData()
				+ reader.getSectionHeader()[reader.getSectionHeader().length - 1].getSizeOfRawData();
		for (int i = start_memory; i < reader.getStream().getData().length; i++)
			reader.getStream().setByte(i, (byte) 0x00);

		reader.save(new File("output.exe"));

	}

	/**
	 * Encrypt a section
	 * @param reader
	 * @param section
	 * @param crypter
	 * @param code_section
	 * @param a
	 * @param b
	 * @param offset
	 * @throws IOException
	 */
	public static void encryptSection(ExecutableReader reader, String section, Payload crypter, int code_section, int a,
			int b, int offset) throws IOException {
		int CODE_SECTION_ID = -1;
		for (int i = 0; i < reader.getSectionHeader().length; i++)
			if (reader.getSectionHeader()[i].getName().trim().equalsIgnoreCase(section)) {
				CODE_SECTION_ID = i;
				break;
			}
		int CODE_FROM = 0;
		int CODE_SIZE = 0;
		if (CODE_SECTION_ID != -1) {
			IMAGE_SECTION_HEADER CODE_SECTION = reader.getSectionHeader()[CODE_SECTION_ID];
			CODE_FROM = reader.getOptionalHeader().getImageBase() + CODE_SECTION.getVirtualAddress() + offset;
			CODE_SIZE = CODE_SECTION.getSizeOfRawData() - offset;

			int in = 0;
			int xor = 0;
			for (int i = CODE_SECTION.getPointerToRawData() + offset; i < CODE_SECTION.getPointerToRawData() + offset
					+ CODE_SIZE; i++) {
				xor = ((((in & 0xF0) * (in & 0x0F)) & 0xFF) + 0x37) - 0x13;
				reader.getStream().setByte(i, (byte) (reader.getStream().getByte(i) ^ (xor & 0xFF)));
				in++;
			}
		}
		ModifyPE.replaceInt(reader, crypter, new MemorySection(reader.getSectionHeader()[code_section]), a,
				CODE_SIZE); //
		ModifyPE.replaceInt(reader, crypter, new MemorySection(reader.getSectionHeader()[code_section]), b,
				CODE_FROM); //
	}

	/**
	 * Return the offset to the loaded address of a specific import in an import table
	 * @param imp the import table to look at
	 * @param dll the DLL the import is in
	 * @param name the name of the import
	 * @param ordinal alternatively to the name an ordinal can be provided
	 * @return an offset to the future position of the address within loaded memory
	 * @throws IOException something went wrong while parsing
	 */
	public static int getOffsetOfTableValue(DescriptorImport imp, String dll, String name, int ordinal)
			throws IOException {
		IMAGE_IMPORT_DESCRIPTOR[] imports = imp.getImports();
		for (IMAGE_IMPORT_DESCRIPTOR i : imports) {
			if (!i.getDLLName().equalsIgnoreCase(dll))
				continue;
			try {
				IMAGE_THUNK_DATA[] impos = i.parseImportTable();
				int address_size = 4; // size for 32bit
				int offsetWithinThunk = i.getFirstThunk() - address_size;
				for (IMAGE_THUNK_DATA impo : impos) {
					offsetWithinThunk += address_size;
					if (name != null && (impo.getName() == null || !impo.getName().equalsIgnoreCase(name)))
						continue;
					if (name == null && impo.getOrdinal() != ordinal)
						continue;
					return offsetWithinThunk;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return 0;
	}

	/**
	 * Parse an import table into an ArrayList of copied imports
	 * @param imp the import table to copy
	 * @return the copied import table
	 * @throws IOException parsing something went wrong
	 */
	public static ArrayList<COPY_IMPORT> parseTableValue(DescriptorImport imp) throws IOException {
		ArrayList<COPY_IMPORT> l = new ArrayList<COPY_IMPORT>();
		IMAGE_IMPORT_DESCRIPTOR[] imports = imp.getImports(); // the imports of the import table
		for (IMAGE_IMPORT_DESCRIPTOR i : imports) {
			try {
				IMAGE_THUNK_DATA[] impos = i.parseImportTable(); //parse the THUNK's into an array
				int address_size = 4; // size for 32bit
				int offsetWithinThunk = i.getFirstThunk() - address_size;
				for (IMAGE_THUNK_DATA impo : impos) {
					offsetWithinThunk += address_size;
					l.add(new COPY_IMPORT(i.getDLLName(), impo.getName(), impo.getOrdinal(), offsetWithinThunk));
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return l;
	}

	/**
	 * Print out the data of an import table
	 * @param imp the import table
	 * @throws IOException error when reading the import table
	 */
	public static void dumpAddresses(DescriptorImport imp) throws IOException {
		System.out.println(Integer.toHexString(imp.offset()));
		IMAGE_IMPORT_DESCRIPTOR[] imports = imp.getImports();
		for (IMAGE_IMPORT_DESCRIPTOR i : imports) {
			System.out.println(Integer.toHexString(i.offset()) + " - " + i.getDLLName());
			try {
				IMAGE_THUNK_DATA[] impos = i.parseImportTable();
				for (IMAGE_THUNK_DATA impo : impos) {
					System.out.println("   " + Integer.toHexString(impo.offset()) + " - " + impo.getName());
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	//a class for representing the copied inputs
	public static class COPY_IMPORT {
		String dll;
		String imp;
		int ordinal;
		// ordinal import needed
		int offset_thunk;

		public COPY_IMPORT(String d, String i, int ord, int o) {
			dll = d;
			imp = i;
			ordinal = ord;
			offset_thunk = o;
		}
	}
}
