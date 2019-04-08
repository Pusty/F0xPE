package pusty.f0xpe.payload;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;

import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.location.Address;
import pusty.f0xpe.location.MemorySection;
import pusty.f0xpe.pe.DescriptorImport;
import pusty.f0xpe.pe.ExecutableReader;
import pusty.f0xpe.pe.IMAGE_OPTIONAL_HEADER32;
import pusty.f0xpe.pe.IMAGE_SECTION_HEADER;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_IMPORT_BY_NAME;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_IMPORT_DESCRIPTOR;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_THUNK_DATA;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_THUNK_DATA32;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_THUNK_DATA64;

/**
 * A Utility class to inject code and otherwise interact with PE Files
 */
public class ModifyPE {
	
	/**
	 * Fill a section "sec" with "amount" bytes "fill" with an offset "offset"
	 * @param reader the mapped binary
	 * @param sec the section to fill
	 * @param fill the byte to fill into the section
	 * @param offset the offset within the section
	 * @param amount the amount of bytes to fill
	 * @return whether setting filling the section was successful
	 */
	public static boolean fill(ExecutableReader reader, MemorySection sec,
			byte fill, int offset, int amount) {
		if (sec.getSize() < fill)
			return false;
		for (int i = 0; i < amount; i++) {
			try {
				reader.getStream().setByte(sec.getOffsetFrom() + i + offset,fill);
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		return true;
	}

	/**
	 * Inject payload into section with a given offset within the section
	 * @param reader the mapped binary
	 * @param payload the payload to inject into the section
	 * @param sec the section the code gets injected to
	 * @param offset offset within the section to inject to
	 * @return whether injecting was successful
	 */
	public static boolean inject(ExecutableReader reader, Payload payload,
			MemorySection sec, int offset) {
		if (sec.getSize() < payload.getSize())
			return false;
		for (int i = 0; i < payload.getSize(); i++) {
			try {
				reader.getStream().setByte(sec.getOffsetFrom() + i + offset,
						payload.getPayload()[i]);
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		return true;
	}
	/**
	 * Inject payload into section
	 * @param reader the mapped binary
	 * @param payload the payload to inject into the section
	 * @param sec the section the code gets injected to
	 * @return whether injecting was successful
	 */
	public static boolean inject(ExecutableReader reader, Payload payload,
			MemorySection sec) {
		return inject(reader, payload, sec, 0);
	}
	/**
	 * Update characteristics and entry point for a specific section
	 * @param reader the mapped binary
	 * @param payload the payload within the section
	 * @param sec the section to set the entry point to
	 * @return whether setting entry point was successful
	 */
	public static boolean update(ExecutableReader reader, Payload payload,
			MemorySection sec) {
		return update(reader, payload.getSize(), sec, true);
	}
	/**
	 * Update binaries characteristics and entry point to a specific section
	 * @param reader the mapped binary
	 * @param size the size of the injected payload
	 * @param sec the section the new code is in
	 * @param setCharacter whether the characteristics should be set to allow everything
	 * @return whether setting entry point was successful
	 */
	public static boolean update(ExecutableReader reader, int size,
			MemorySection sec, boolean setCharacter) {
		// as the cave is most likely at the end the virtual size has to be
		// increased
		// I'm assuming that if the cave isn't at the end and the size is
		// increased for no reason , it still doesn't crash
		sec.getSection().setVirtualSize(
			sec.getSection().getVirtualSize() + size);
		// Makes Section Executable, Readable and Writable
		// This might be good for a default setting, but it HAS be changeable
		// A read,write and executable section IS suspicious and most likely not
		// necessary
		
		if(setCharacter)
			sec.getSection().setCharacteristics(
					sec.getSection().getCharacteristics()
							| IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_EXECUTE
							| IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_READ
							| IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_WRITE);
		
		//Save old EntryPoint and MemorySection Settings
		sec.putData("returnMode ", true);
		sec.putData("is64bit", (!reader.is32bit()));
		if(!reader.is32bit())
			sec.putData("returnAddr", (long)(reader.getOptionalHeader().getAddressOfEntryPoint()));
		else
			sec.putData("returnAddr", (int)(reader.getOptionalHeader().getAddressOfEntryPoint()));
		// Sets Address of Entry to (Offset from Section Head to
		// Payload)+Virtual Address of Section
		System.out.println(Long.toHexString(reader.getOptionalHeader().getAddressOfEntryPoint()));
		System.out.println(Long.toHexString(sec.getAddressFrom()));
		reader.getOptionalHeader().setAddressOfEntryPoint(sec.getAddressFrom());
		return true;
	}
	
	/**
	 * Searches for the 32bit integer "find" within the section and replaces the first found instance with "replace" if found
	 * @param reader the mapped binary
	 * @param payload the payload contained in section (defines upper boarder for searching)
	 * @param sec the section to search in
	 * @param find the 32bit integer to find
	 * @param replace the 32bit integer that replaces "find"
	 * @return whether replacing was successful
	 */
	public static boolean replaceInt(ExecutableReader reader, Payload payload,
			MemorySection sec, int find, int replace) {
		for (int i = 0; i < payload.getSize(); i++) {
			try {
					if(reader.getStream().getInt(sec.getOffsetFrom() + i)==find) {
						reader.getStream().setInt(sec.getOffsetFrom() + i, replace);
						return true;
					}				
			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("[!] Didn't find Replace Value!");
				return false;
			}
		}
		System.out.println("[!] Didn't find Replace Value!");
		return false;
	}
	
	/**
	 * Searches for the 32bit integer "find" within the section and replaces the all found instances with "replace" if found
	 * @param reader the mapped binary
	 * @param find the 32bit integer to find
	 * @param replace the 32bit integer that replaces "find"
	 */
	public static void replaceAllInt(ExecutableReader reader, int find, int replace) {
		for (int i = 0; i < reader.getStream().getData().length-3; i++) {
			try {
					if(reader.getStream().getInt(i)==find) {
						reader.getStream().setInt(i, replace);
					}				
			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("[!] Didn't find Replace Value!");
			}
		}
	}
	
	
	/**
	 * Search for the 32bit integer "find" and returns the index of its first occurrence
	 * @param reader the mapped binary
	 * @param payload the payload determening the amount of bytes that get searched for the integer
	 * @param sec the memory section to search in, determening the start index
	 * @param find the 32bit integer to find
	 * @return the index the value was found at. -1 if not found
	 */
	public static int searchInt(ExecutableReader reader, Payload payload,
			MemorySection sec, int find) {
		for (int i = 0; i < payload.getSize(); i++) {
			try {
					if(reader.getStream().getInt(sec.getOffsetFrom() + i)==find) {
						return sec.getOffsetFrom() + i;
					}				
			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("[!] Didn't find Search Value!");
				return -1;
			}
		}
		System.out.println("[!] Didn't find Search Value!");
		return -1;
	}
	
	/**
	 * Searches for the 32bit integer "find" within a section and replaces it with the saved return address of the section
	 * @param reader the mapped binary
	 * @param payload the payload contained in the section (defines upper border for searching)
	 * @param sec the section to search in which contains the return address
	 * @param find the address to find and replace
	 * @return whether replacing was successful
	 */
	public static boolean filterReturn(ExecutableReader reader, Payload payload,
			MemorySection sec, Address find) {
		if(!reader.is32bit())
			System.out.println("[*] Trying to replace 0x" + Long.toHexString(find.getAddr64()).toUpperCase() + " with return address");
		else
			System.out.println("[*] Trying to replace 0x" + Integer.toHexString(find.getAddr32()).toUpperCase() + " with return address");
		boolean is64bit = (boolean)sec.getData("is64bit");
		for (int i = 0; i < payload.getSize(); i++) {
			try {
				if(is64bit) {
					if(reader.getStream().getLong(sec.getOffsetFrom() + i)==find.getAddr64()) {
						reader.getStream().setLong(sec.getOffsetFrom() + i, (long)sec.getData("returnAddr"));
						return true;
					}
				}else {
					if(reader.getStream().getInt(sec.getOffsetFrom() + i)==find.getAddr32()) {
						reader.getStream().setInt(sec.getOffsetFrom() + i, (int)sec.getData("returnAddr"));
						return true;
					}				
				}
			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("[!] Didn't find Replace Address!");
				return false;
			}
		}
		System.out.println("[!] Didn't find Replace Address!");
		return false;
	}
	/**
	 * Try to find "find" within mapped binary section "sec" (up to the size of the payload) and replace it with "jumpTo"
	 * @param reader the mapped binary
	 * @param payload the payload within section (defines upper border for the search)
	 * @param sec the section to search
	 * @param find the address to find
	 * @param jumpTo the address that replaces "find"
	 * @return whether replacing was successful
	 */
	public static boolean filterJump(ExecutableReader reader, Payload payload,
			MemorySection sec, Address find, Address jumpTo) {
		return filterJump(reader, payload.getSize(), sec, find, jumpTo, 0);
	}
	/**
	 * Try to find "find" within the mapped binary section "sec" from "offset" to "size" and replace it with "jumpTo" if found
	 * @param reader the mapped binary
	 * @param size the size of the section
	 * @param sec the section to filter
	 * @param find the address to find
	 * @param jumpTo the address that replaces "find"
	 * @param offset offset within the section to start searching from
	 * @return whether replacing was successful
	 */
	public static boolean filterJump(ExecutableReader reader, int size,
			MemorySection sec, Address find, Address jumpTo, int offset) {
		for (int i = offset; i < size; i++) {
			try {
				if(!reader.is32bit()) {
					if(reader.getStream().getInt(sec.getOffsetFrom() + i)==find.getAddr32()) {
						long toAddr = jumpTo.getAddr64();
						long fromAddr = sec.getAddressFrom();
						int result = (int)(toAddr-fromAddr) - (i+4); //calculate offset from current position (a jump) to position
						reader.getStream().setInt(sec.getOffsetFrom() + i, result);
						//System.out.println("[*] Replaced 0x" + Integer.toHexString(find.getAddr32()).toUpperCase() + " with relative jump address");
						return true;
					}
				}else {
					if(reader.getStream().getInt(sec.getOffsetFrom() + i)==find.getAddr32()) {
						int toAddr = jumpTo.getAddr32();
						int fromAddr = sec.getAddressFrom();
						int result = (toAddr-fromAddr) - (i+4); //calculate offset from current position (a jump) to position
						reader.getStream().setInt(sec.getOffsetFrom() + i, result);
						System.out.println("[*] Replaced 0x" + Integer.toHexString(result).toUpperCase() + " with relative jump address");
						return true;
					}				
				}
			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("[!] Didn't find Replace Address!");
				return false;
			}
		}
		System.out.println("[!] Didn't find Replace Address!");
		return false;
	}

	/**
	 * Fixes the actual PE Section the MemorySection is in
	 * <br>This means it increases Virtual Size if needed
	 * @param reader the mapped binary
	 * @param sec the section to check for virtual memory border mistakes
	 */
	public static void fixBorders(ExecutableReader reader, MemorySection sec) {
		int i = sec.getSection().getVirtualSize();
		for(i=sec.getSection().getVirtualSize();i<sec.getSection().getPointerToRawData();i++) {
			try {
				if(reader.getStream().getByte(sec.getSection().getPointerToRawData()+i) == 0)
					break;
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if(i != sec.getSection().getVirtualSize()) {
			System.out.println("[*] Increasing Virtual Size by "+(i-sec.getSection().getVirtualSize())+" Bytes");
			sec.getSection().setVirtualSize(i);
		}
	}
	
	/**
	 * Align value to alignment
	 * @param value the value to align
	 * @param alignment the alignment value
	 * @return the aligned value
	 */
	public static int align(int value, int alignment) {
		
		 return (((value / alignment)+(value%alignment==0?0:1)) * alignment);
		// return (((int)Math.ceil(((float)value) / ((float)alignment))) * alignment);
	}
	
	//public static int createImportTable(ExecutableReader reader, int position) {
	//	return 0;
	//}
	
	/**Replace original import with replacement import of the same DLL
	 * <br>NOTE: Creates a new IMAGE_IMPORT_BY_NAME if the replacement string does not fit in the old structure
	 * <br>NOTE: Not Thread Safe
	 * @param reader the mapped binary 
	 * @param dll the DLL where to replace the import in
	 * @param original the original import
	 * @param replacement the replacement import
	 * @param position the position to add the new structures
	 * @return new position within the section (-1 if not successful)
	 */
	public static int replaceImport(ExecutableReader reader, String dll, String original, String replacement, int position) {
		try {
			//Iterate through all imports
			for(int i=0;i<reader.getOptionalHeader().getImportDescriptor().getImports().length;i++) {
				//Search for the "DLL" with the same name
				if(dll.equalsIgnoreCase(reader.getOptionalHeader().getImportDescriptor().getImports()[i].getDLLName())) {
					IMAGE_IMPORT_DESCRIPTOR desc = reader.getOptionalHeader().getImportDescriptor().getImports()[i];
					IMAGE_THUNK_DATA[] data = desc.parseImportTable();
					for(int a=0;a<data.length;a++) {
						//Search for the "original" import
						if(data[a].getName() != null && original.equals(data[a].getName())) {
						    //if the new name fits in within the olds space DON'T create new structures
							if(replacement.length() <= original.length()) {
								int oldpos = data[a].getNameOffset();
								reader.getStream().setIndex(oldpos);
								IMAGE_IMPORT_BY_NAME newStruct = new IMAGE_IMPORT_BY_NAME(reader);
								newStruct.setHint((short) 0);
								newStruct.setString(replacement);
								reader.getStream().setIndex(position);
								return position;
							}else {
								//Create a new IMAGE_IMPORT_BY_NAME Structure and make the IMAGE_THUNK_DATA point to it
								data[a].setNameOffset(position);
								desc.parseHintNameTable()[a].setNameOffset(position);
								reader.getStream().setIndex(position);
								IMAGE_IMPORT_BY_NAME newStruct = new IMAGE_IMPORT_BY_NAME(reader);
								newStruct.setHint((short) 0);
								newStruct.setString(replacement);
								int result = reader.getStream().getIndex();
								reader.getStream().setIndex(result);
								return result;
							}
						}
					}
					System.err.println("replaceImport didn't find import "+original+" within "+dll);
					return -1;
				}
			}
		}catch(Exception e){ e.printStackTrace(); }
		System.err.println("replaceImport didn't find dll "+dll);
		return -1;
	}
	
	/**
	 * Adds a new section to the binary (if there is enough place to add a new section)
	 * @param reader the mapped binary
	 * @param name the name of the new section
	 * @param size the virtual size of the new binary (raw size etc will get aligned)
	 * @param characterisitcs the characteristics of the new section
	 * @return the id of the new section, -1 if failed to inject
	 */
	public static int injectSection(ExecutableReader reader, String name, int size, int characterisitcs) {
		return injectSection(reader, name, size, characterisitcs, false);
	}
	public static int injectSection(ExecutableReader reader, String name, int size, int characterisitcs, boolean onlyVirtual) {
		int sizeOfSection = reader.getSectionHeader()[0].sizeof();
		//Get offset to section beginning
		int offset = reader.getOptionalHeader().offset() + reader.getFileHeader().getSizeOfOptionalHeader();
		//Add all sections to the offset
		offset = offset + sizeOfSection * reader.getFileHeader().getNumberOfSections();
		//Check if section can be inserted
		if(offset+sizeOfSection >= reader.getOptionalHeader().getSizeOfHeaders()) {
			System.out.println("[!] Not enough space for injecting a section");
			return -1;
		}
		try {
			//Set reader to the offset
			reader.getStream().setIndex(offset);
			//Start mapping the memory
			IMAGE_SECTION_HEADER section = new IMAGE_SECTION_HEADER(reader);
			//Set the name
			section.setName(name);
			int vaddr = (int)(reader.getSectionHeader()[reader.getSectionHeader().length-1].getVirtualSize() + reader.getSectionHeader()[reader.getSectionHeader().length-1].getVirtualAddress());
			int file_alignment = reader.getOptionalHeader().getFileAlignment();
		    int section_alignment = reader.getOptionalHeader().getSectionAlignment();
	    	section.setVirtualAddress(align(vaddr,section_alignment));
			section.setVirtualSize(size);
			byte[] data = new byte[align(size, file_alignment)];
			for(int i=0;i<data.length;i++)
				data[i] = (byte)0x00;
			
			if(!onlyVirtual) {
				section.setSizeOfRawData(data.length);
				int lastOffset = 0;
				for(int i=0;i<reader.getSectionHeader().length;i++)
					if(reader.getSectionHeader()[i].getPointerToRawData() != 0)
						lastOffset = reader.getSectionHeader()[i].getPointerToRawData()+reader.getSectionHeader()[i].getSizeOfRawData();
				section.setPointerToRawData(lastOffset);
			}else {
				section.setSizeOfRawData(0);
				section.setPointerToRawData(0);
				data = new byte[0];
			}
			section.setCharacteristics(characterisitcs);
		    section.setPointerToLinenumbers(0);
		    section.setNumberOfLinenumbers((short)0);
		    section.setPointerToRelocations(0);
		    section.setNumberOfRelocations((short)0);
		    
		    reader.getFileHeader().setNumberOfSections((short) (reader.getFileHeader().getNumberOfSections()+1));
		    //Correct Image Size
		    reader.getOptionalHeader().setSizeOfImage(align(
		       (int) (   reader.getOptionalHeader().getSizeOfHeaders()
		        +  section.getVirtualAddress()
		        +  section.getVirtualSize()),
		        section_alignment
		    ));
		    
		    //Reset Sizes to calculate them in a second
		    reader.getOptionalHeader().setSizeOfCode(0);
		    reader.getOptionalHeader().setSizeOfInitializedData(0);
		    reader.getOptionalHeader().setSizeOfUninitializedData(0);
		    
		    //Create new array for data
		    byte[] newdata = new byte[reader.getStream().getData().length+data.length];
		    //Remap memory
		    for(int i=0;i<section.getPointerToRawData();i++) //before section
		    	newdata[i] = reader.getStream().getData()[i];
		    for(int i=0;i<data.length;i++) //section insert
		    	newdata[i+section.getPointerToRawData()] = data[i];
		    for(int i=0;i<reader.getStream().getData().length-section.getPointerToRawData();i++) //after section
		    	newdata[section.getPointerToRawData()+data.length+i] = reader.getStream().getData()[section.getPointerToRawData()+i];
		    //Load remapped memory into reader
		    ExecutableReader.rewrite(reader, newdata);
		    //Resize the optional header entries
		    for(int i=0;i<reader.getSectionHeader().length;i++) {
		    	if((reader.getSectionHeader()[i].getCharacteristics() & IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_CODE) != 0)
		    		reader.getOptionalHeader().setSizeOfCode(reader.getOptionalHeader().getSizeOfCode()
		    	+   reader.getSectionHeader()[i].getSizeOfRawData());
		    	if((reader.getSectionHeader()[i].getCharacteristics() & IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
		    		reader.getOptionalHeader().setSizeOfInitializedData(reader.getOptionalHeader().getSizeOfInitializedData()
		    	+   reader.getSectionHeader()[i].getSizeOfRawData());
		    	if((reader.getSectionHeader()[i].getCharacteristics() & IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
		    		reader.getOptionalHeader().setSizeOfUninitializedData(reader.getOptionalHeader().getSizeOfUninitializedData()
		    	+   reader.getSectionHeader()[i].getSizeOfRawData());
		    }
		    return reader.getSectionHeader().length-1;
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
	}
	
	/**
	 * Remove the last section of the file. Does nothing if only one section is left.
	 * @param reader the mapped binary
	 */
	public static void removeLastSection(ExecutableReader reader) {
		if(reader.getSectionHeader().length <= 1) return;
		try {
			IMAGE_SECTION_HEADER section = reader.getSectionHeader()[reader.getSectionHeader().length-1];    
		    int section_alignment = reader.getOptionalHeader().getSectionAlignment();
		    //Correct Image Size
		    reader.getFileHeader().setNumberOfSections((short) (reader.getFileHeader().getNumberOfSections()-1));
		    reader.getOptionalHeader().setSizeOfImage(align(
		       (int) (   reader.getOptionalHeader().getSizeOfHeaders()
		        -  section.getVirtualSize()),
		        section_alignment
		    ));
		    //Reset Sizes to calculate them in a second
		    reader.getOptionalHeader().setSizeOfCode(0);
		    reader.getOptionalHeader().setSizeOfInitializedData(0);
		    reader.getOptionalHeader().setSizeOfUninitializedData(0);
		    //Create new array for data
		    for(int i=section.offset();i<section.offset()+section.sizeof();i++) //clean section
		    	reader.getStream().setByte(i, (byte) 0);
		    ExecutableReader.rewrite(reader, reader.getStream().getData());
		    //Load remapped memory into reader
		    //Resize the optional header entries
		    for(int i=0;i<reader.getSectionHeader().length;i++) {
		    	if((reader.getSectionHeader()[i].getCharacteristics() & IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_CODE) != 0)
		    		reader.getOptionalHeader().setSizeOfCode(reader.getOptionalHeader().getSizeOfCode()
		    	+   reader.getSectionHeader()[i].getSizeOfRawData());
		    	if((reader.getSectionHeader()[i].getCharacteristics() & IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
		    		reader.getOptionalHeader().setSizeOfInitializedData(reader.getOptionalHeader().getSizeOfInitializedData()
		    	+   reader.getSectionHeader()[i].getSizeOfRawData());
		    	if((reader.getSectionHeader()[i].getCharacteristics() & IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
		    		reader.getOptionalHeader().setSizeOfUninitializedData(reader.getOptionalHeader().getSizeOfUninitializedData()
		    	+   reader.getSectionHeader()[i].getSizeOfRawData());
		    }
		    
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Replaces references of the current import table to the new one at "newTable"
	 * <br>NOTE: NOT THREAD SAFE
	 * <br>ANOTHER NOTE: (TODO) THIS IS VERY SLOW FOR BIG TABLES
	 * <br>WARNING: DIDN'T WORK FOR 64bit (TODO)
	 * <br>THIS IS ONLY EVEN REMOTLY FEASABLE BECAUSE OF JAVA-VM OPTIMIZATION MAGIC
	 * @param reader the binary to read from
	 * @param newTable the offset of the new import table
	 */
	
	public static void replaceTableReferences(ExecutableReader reader, int newTable) {
		int tmp = reader.getStream().getIndex();
		try {
			//Collect old thunks
			HashMap<IMAGE_THUNK_DATA, String> originalThunkList = new HashMap<IMAGE_THUNK_DATA, String>();
			for(IMAGE_IMPORT_DESCRIPTOR desc:reader.getOptionalHeader().getImportDescriptor().getImports()) {
				IMAGE_THUNK_DATA[] thunkData = desc.parseImportTable();
				for(IMAGE_THUNK_DATA thunk:thunkData)
					originalThunkList.put(thunk, desc.getDLLName());
			}
			//Collect new thunks
			HashMap<IMAGE_THUNK_DATA, String> newThunkList = new HashMap<IMAGE_THUNK_DATA, String>();
			reader.getStream().setIndex(newTable);
			DescriptorImport descNew = new DescriptorImport(reader);
			for(IMAGE_IMPORT_DESCRIPTOR desc:descNew.getImports()) {
				IMAGE_THUNK_DATA[] thunkData = desc.parseImportTable();
				for(IMAGE_THUNK_DATA thunk:thunkData)
					newThunkList.put(thunk,desc.getDLLName());
			}
			//Search for matching new thunks
			for(Entry<IMAGE_THUNK_DATA, String> entry:originalThunkList.entrySet()) {
				IMAGE_THUNK_DATA found = null;
				for(Entry<IMAGE_THUNK_DATA, String> search:newThunkList.entrySet()) {
					if(!entry.getValue().equalsIgnoreCase(search.getValue())) continue;
					if(entry.getKey().isOrdinal() != search.getKey().isOrdinal()) continue;
					if(entry.getKey().isOrdinal()) {
						if(entry.getKey().getOrdinal() == search.getKey().getOrdinal()) {
							found = search.getKey();
							break;
						}continue;
					}else {
						if(entry.getKey().getName().equals(search.getKey().getName())) {
							found = search.getKey();
							break;
						}continue;
					}
				}
				//REPLACE REFERENCES TO OLD THUNK WITH NEW ONE (AND ZERO OLD NOT FOUND ONES)
				//NOTE: ONLY REPLACES REFERENCES BELOW/BEFORE IMPORT TABLE AND WITHIN CODE SECTIONS
				for(IMAGE_SECTION_HEADER section:reader.getSectionHeader()) {
					if((section.getCharacteristics()&IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_CODE) == 0)continue;
					if(reader.is32bit()) {
						int compare = (reader.offset2rva(entry.getKey().offset()).getAddr32() + reader.getOptionalHeader().getImageBase());
						int newContent = 0xDEADC0DE;
						if(found != null)
							newContent = (reader.offset2rva(found.offset()).getAddr32() + reader.getOptionalHeader().getImageBase());
						else
							System.out.println("[?] Lost reference to "+entry.getValue()+": "+(entry.getKey().isOrdinal()?entry.getKey().getOrdinal():entry.getKey().getName()));
						
						for(int i=0;i<section.getSizeOfRawData()-3;i++) {
							if(reader.getStream().getInt(section.getPointerToRawData()+i) == compare) {
								reader.getStream().setInt(section.getPointerToRawData()+i, newContent);
							}
						}
					}else {
						long compare = (reader.offset2rva(entry.getKey().offset()).getAddr64() + reader.getOptionalHeader64().getImageBase64());
						long newContent = 0xDEADC0DE;
						if(found != null)
							newContent = (reader.offset2rva(found.offset()).getAddr64() + reader.getOptionalHeader64().getImageBase64());
						else
							System.out.println("[?] Lost reference to "+entry.getValue()+": "+(entry.getKey().isOrdinal()?entry.getKey().getOrdinal():entry.getKey().getName()));
						for(int i=0;i<section.getSizeOfRawData()-7;i++) {
							if(reader.getStream().getLong(section.getPointerToRawData()+i) == compare) {
								reader.getStream().setLong(section.getPointerToRawData()+i, newContent);
							}
						}
					}
				}
			}
		}catch(Exception e) {
			e.printStackTrace();
		}
		reader.getStream().setIndex(tmp);
	}
	
	/**
	 * Clears the current import table and zeros out all references memory of it
	 * @param reader the mapped binary
	 * @throws Exception clearing failed for some reason
	 */
	public static void clearTable(ExecutableReader reader) throws Exception {
		DescriptorImport imp = reader.getOptionalHeader().getImportDescriptor();
		for(IMAGE_IMPORT_DESCRIPTOR desc:imp.getImports()) {
			IMAGE_THUNK_DATA[] dataArray = desc.parseImportTable();
			for(IMAGE_THUNK_DATA data:dataArray) {
				if(data.isOrdinal())
					data.setOrdinal(0);
				else {
					data.getImportByName().setHint((short)0);
					data.getImportByName().setString("");
					data.setNameOffset(0);
				}
			}
			dataArray = desc.parseHintNameTable();
			for(IMAGE_THUNK_DATA data:dataArray) {
				if(data.isOrdinal())
					data.setOrdinal(0);
				else {
					data.getImportByName().setHint((short)0);
					data.getImportByName().setString("");
					data.setNameOffset(0);
				}
			}
			int length = desc.getDLLName().length();
			for(int i=0;i<length;i++)
				reader.getStream().setByte(reader.rva2offset(new Address(desc.getName()))+i, (byte)0);
			
			desc.setCharacteristics(0);
			desc.setFirstThunk(0);
			desc.setForwarderChain(0);
			desc.setName(0);
			desc.setOriginalFirstThunk(0);
			desc.setTimeDateStamp(0);
		}
		reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IMPORT].setVirtualAddresss(0);
		reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IMPORT].setSize(0);
		reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IAT].setVirtualAddresss(0);
		reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IAT].setSize(0);
		reader.getOptionalHeader().getDirectoryEntries()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IMPORT] = null;
	}
	
	/**
	 * An Editable Import Table
	 */
	public static class EditableImportTable {
		
		//the entries of this editable import table
		private final ArrayList<EditableImportEntry> entries;
		
		/** Create a new editable import table */
		public EditableImportTable() {
			this.entries = new ArrayList<EditableImportEntry>();
		}
		
		/**
		 * Get the entry list of the imports of this table.
		 * @return the list of import entries
		 */
		public ArrayList<EditableImportEntry> getEntries() {
			return this.entries;
		}
		
		/**
		 * Process and write this dynamic table into a binary at a given positon.
		 * @param reader the mapped binary
		 * @param position the position to write to
		 */
		public void writeTable(ExecutableReader reader, int position) {
			writeTable(reader, position, true);
		}
		
		/**
		 * Writes this Import Table to "position", re-references everything and zeros the current import table
		 * <br>NOTE: NOT THREAD SAFE
		 * <br>ANOTHER NOTE: DOES NOT CHECK IF ENOUGH MEMORY IS AVAILABLE, WATCH OUT (TODO)
		 * <br>WARNING: DIDN'T WORK FOR 64bit (TODO)
		 * @param reader the mapped binary
		 * @param position the position to write to
		 * @param replaceOld replace old table and references to it
		 */
		public int writeTable(ExecutableReader reader, int position, boolean replaceOld) {
			int lastIndex = 0;
			int tmp = reader.getStream().getIndex();
			try {
				
				IMAGE_IMPORT_DESCRIPTOR[] descriptor = new IMAGE_IMPORT_DESCRIPTOR[this.entries.size()];
				int offsetAfterDesc = position + ReadableObject.sizeof(new IMAGE_IMPORT_DESCRIPTOR(reader)) * (entries.size()+1);
				
				ArrayList<Integer> stringPosition = new ArrayList<Integer>();
				
				//Save strings of the DLL Names
				reader.getStream().setIndex(offsetAfterDesc);
				for(int i=0;i<descriptor.length;i++) {
					stringPosition.add(reader.offset2rva(reader.getStream().getIndex()).getAddr32());
					reader.getStream().writeString(entries.get(i).getDLLName());
				}
				
				int pointerSize = reader.is32bit()?4:8;
				int iat = reader.getStream().getIndex();
				int hint = iat+(amountOfEntries()*pointerSize + entries.size()*pointerSize);
				offsetAfterDesc = hint+(amountOfEntries()*pointerSize + entries.size()*pointerSize);
				ArrayList<Integer> nameArray = new ArrayList<Integer>();
				//Save strings of the imports (IMAGE_IMPORT_BY_NAMEs)
				reader.getStream().setIndex(offsetAfterDesc);
				for(EditableImportEntry entryList:entries) {
					for(Object entry:entryList.getImport()) {
						if(entry instanceof String) {
							nameArray.add(reader.offset2rva(reader.getStream().getIndex()).getAddr32());
							reader.getStream().setShort(reader.getStream().readAddrShort(), 0);
							reader.getStream().writeString(entry.toString());
						}
					}
				}
				lastIndex = reader.getStream().getIndex(); //highest memory address of table
				
				ArrayList<Integer> originalArray = writePointerTable(reader, nameArray, iat);
				ArrayList<Integer> firstArray = writePointerTable(reader, nameArray, hint);
				
				reader.getStream().setIndex(position);
				for(int i=0;i<descriptor.length;i++) {
					descriptor[i] = new IMAGE_IMPORT_DESCRIPTOR(reader);
					descriptor[i].setOriginalFirstThunk(reader.offset2rva(originalArray.get(i)).getAddr32());
					//descriptor[i].setOriginalFirstThunk(0);
					descriptor[i].setTimeDateStamp(0);
					descriptor[i].setForwarderChain(0);
					descriptor[i].setName(stringPosition.get(i));
					descriptor[i].setFirstThunk(reader.offset2rva(firstArray.get(i)).getAddr32());
				}
				
				IMAGE_IMPORT_DESCRIPTOR none = new IMAGE_IMPORT_DESCRIPTOR(reader);
				none.setOriginalFirstThunk(0);
				none.setCharacteristics(0);
				none.setTimeDateStamp(0);
				none.setForwarderChain(0);
				none.setName(0);
				none.setFirstThunk(0);
				
				if(replaceOld) {
					replaceTableReferences(reader, position);
					if(reader.getOptionalHeader().getImportDescriptor().offset() != position)
						clearTable(reader);
				}
				
				
				//OK NOW THE NEW IMPORT TABLE IS OFFICIAL
				reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IMPORT].setVirtualAddresss(reader.offset2rva(position).getAddr32());
				reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IMPORT].setSize(ReadableObject.sizeof(new IMAGE_IMPORT_DESCRIPTOR(reader)) * (entries.size()));
				reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IAT].setVirtualAddresss(reader.offset2rva(iat).getAddr32());
				reader.getOptionalHeader().getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IAT].setSize((amountOfEntries())*pointerSize);
				reader.getOptionalHeader().parseImportTable();
			}catch(Exception e) {
				e.printStackTrace();
			}
			reader.getStream().setIndex(tmp);
			return lastIndex;
		}
		
		/**
		 * Write a table of of pointers to a specific position into the mapped binary.
		 * @param reader the mapped binary
		 * @param pointerArray the array of pointers
		 * @param pos the position to write to
		 * @return an ArrayList containing the positions the pointers were written to
		 * @throws IOException when read out of bounds or other IO Error occurred within the stream
		 */
		private ArrayList<Integer> writePointerTable(ExecutableReader reader, ArrayList<Integer> pointerArray, int pos) throws IOException {
			ArrayList<Integer> arrayList = new ArrayList<Integer>();
			reader.getStream().setIndex(pos);
			int indexWithinStrings = 0;
			for(EditableImportEntry entryList:entries) {
				arrayList.add(reader.getStream().getIndex());
				for(Object entry:entryList.getImport()) {
					if(entry instanceof String) {
						if(reader.is32bit()) {
							reader.getStream().setInt(reader.getStream().readAddrInt(), pointerArray.get(indexWithinStrings));
						}else{
							reader.getStream().setLong(reader.getStream().readAddrLong(), pointerArray.get(indexWithinStrings));	
						}
						indexWithinStrings++;
					}else if(entry instanceof Integer){
						if(reader.is32bit()) {
							reader.getStream().setInt(reader.getStream().readAddrInt(), ((int)entry) | IMAGE_THUNK_DATA32.IMAGE_ORDINAL_FLAG32);
						}else{
							reader.getStream().setLong(reader.getStream().readAddrLong(), ((int)entry) | IMAGE_THUNK_DATA64.IMAGE_ORDINAL_FLAG64);
						}
					}
				}
				//Zero terminate pointer array
				if(reader.is32bit()) {
					reader.getStream().setInt(reader.getStream().readAddrInt(), 0);
				}else{
					reader.getStream().setLong(reader.getStream().readAddrLong(), 0);	
				}
			}
			return arrayList;
		}
		
		/**
		 * Parse the current import table of a mapped binary and make an editable import table out of it
		 * @param reader the mapped binary
		 * @return the import table of the binary in a editable format
		 */
		public static EditableImportTable fromReader(ExecutableReader reader) {
			try {
				EditableImportTable editableTable = new EditableImportTable();
				DescriptorImport table = reader.getOptionalHeader().getImportDescriptor();
				for(IMAGE_IMPORT_DESCRIPTOR image:table.getImports()) {
					EditableImportEntry entry = new EditableImportEntry(image.getDLLName());
					IMAGE_THUNK_DATA[] entries = image.parseImportTable();
					for(IMAGE_THUNK_DATA e:entries) {
						if(e.isOrdinal())
							entry.addOrdinal(e.getOrdinal());
						else
							entry.addNamed(e.getName());
					}
					editableTable.getEntries().add(entry);
				}
				return editableTable;
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		
		/**
		 * Dump the EditableImportTable and its imports to stdout
		 */
		public void dump() {
			for(EditableImportEntry e:entries) {
				System.out.println(e.getDLLName());
				for(Object o:e.getImport()) {
					if(o instanceof Integer)
						System.out.println(" Ordinal: "+o);
					else
						System.out.println(" Named:   "+o);
				}
			}
		}
		
		/**
		 * Returns the amount of registered entries
		 * @return the amount of entries within the EditableImportEntry list
		 */
		public int amountOfEntries() {
			int amount = 0;
			for(EditableImportEntry entryList: entries)
				amount += entryList.getImport().size();
			return amount;
		}
	}
	
	/**
	 * Class for EditableImportTable, a wrapper for import entries and to modify existed tables
	 */
	public static class EditableImportEntry {
		//the name of the dynamic linked library
		private String dllname;
		//an ArrayList containing the imports which may have different formats
		private ArrayList<Object> imports;
		/**
		 * Creates a new entry
		 * @param name name of the dynamic linked library this import represents
		 */
		public EditableImportEntry(String name) {
			this.dllname = name;
			this.imports = new ArrayList<Object>();
		}
		/**
		 * An ArrayList containing all the imports (String/Named or Integer/Ordinal)
		 * @return an ArrayList to add/remove imports
		 */
		public ArrayList<Object> getImport() {
			return imports;
		}
		/**
		 * Add a named import
		 * @param str function to import by this DLL
		 */
		public void addNamed(String str) {
			imports.add(str);
		}
		/**
		 * Add an ordinal import
		 * @param ord function to import by this DLL
		 */
		public void addOrdinal(int ord) {
			imports.add(Integer.valueOf(ord));
		}
		/**
		 * Returns the name of this DLL Import
		 * @return the DLL this entry represents
		 */
		public String getDLLName() {
			return dllname;
		}
		/**
		 * Set the name of this DLL
		 * @param name the new DLL name this entry represents
		 */
		public void setDLLName(String name) {
			dllname = name;
		}
		
	}
}
