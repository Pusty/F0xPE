package pusty.f0xpe.pe;

import java.io.IOException;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.location.Address;
import pusty.f0xpe.pe.ExecutableReader;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_IMPORT_DESCRIPTOR;
import pusty.f0xpe.pe.DescriptorImport.IMAGE_THUNK_DATA;
import pusty.f0xpe.pe.DescriptorResource.IMAGE_RESOURCE_DIRECTORY;
import pusty.f0xpe.pe.DescriptorResource.IMAGE_RESOURCE_DIRECTORY_ENTRY;

/**
 * A class representing the IMAGE_OPTIONAL_HEADER32 structure in a given binary reader.
 * <br>Reference: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header
 * <br>Header: winnt.h
 */
public class IMAGE_OPTIONAL_HEADER32 extends ReadableObject{

	//The descriptions of these fields are copy pasted from the Microsoft documentation
	
	//
	// Standard fields.
	//
	// private final static int PE32 = 0x10b;
	// private final static int PE32P = 0x20b;

	/** The state of the image file. */
	protected int Magic; // magic number (0x10b = PE32; 0x20b = PE32+)
	/** The major version number of the linker. */
	protected int MajorLinkerVersion; // Linker Information
	/** The minor version number of the linker. */
	protected int MinorLinkerVersion; // Linker Information
	/** The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections. */
	protected int SizeOfCode; // Length of Executable Code
	/** The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections. */
	protected int SizeOfInitializedData; // Length of Initialized Data
	/** The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections. */
	protected int SizeOfUninitializedData; // Length of Uninitialized Data
	/** A pointer to the entry point function, relative to the image base address. For executable files, this is the starting address. For device drivers, this is the address of the initialization function. The entry point function is optional for DLLs. When no entry point is present, this member is zero. */
	protected int AddressOfEntryPoint; // Entry for PE
	/** A pointer to the beginning of the code section, relative to the image base. */
	protected int BaseOfCode; // Start of .text (Code)
	/** A pointer to the beginning of the data section, relative to the image base. */
	protected int BaseOfData; // Start of .bss (Uninitialized Data) (not
								// included in PE32+)
	//
	// NT additional fields.
	//
	/** The preferred address of the first byte of the image when it is loaded in memory. This value is a multiple of 64K bytes. The default value for DLLs is 0x10000000. The default value for applications is 0x00400000, except on Windows CE where it is 0x00010000. */
	protected int ImageBase;
	/** The alignment of sections loaded in memory, in bytes. This value must be greater than or equal to the FileAlignment member. The default value is the page size for the system. */
	protected int SectionAlignment;
	/** The alignment of the raw data of sections in the image file, in bytes. The value should be a power of 2 between 512 and 64K (inclusive). The default is 512. If the SectionAlignment member is less than the system page size, this member must be the same as SectionAlignment. */
	protected int FileAlignment;
	/** The major version number of the required operating system. */
	protected int MajorOperatingSystemVersion;
	/** The minor version number of the required operating system. */
	protected int MinorOperatingSystemVersion;
	/** The major version number of the image. */
	protected int MajorImageVersion;
	/** The minor version number of the image. */
	protected int MinorImageVersion;
	/** The major version number of the subsystem. */
	protected int MajorSubsystemVersion;
	/** The minor version number of the subsystem. */
	protected int MinorSubsystemVersion;
	/** This member is reserved and must be 0. */
	protected int Reserved1;
	/** The size of the image, in bytes, including all headers. Must be a multiple of SectionAlignment. */
	protected int SizeOfImage;
	/** The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member: e_lfanew member of IMAGE_DOS_HEADER, 4 byte signature, size of IMAGE_FILE_HEADER, size of optional header, size of all section headers */
	protected int SizeOfHeaders;
    /** The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process. */
	protected int CheckSum;
	/** The subsystem required to run this image. */
	protected int Subsystem;
	/** The DLL characteristics of the image. */
	protected int DllCharacteristics;
	/** The number of bytes to reserve for the stack. Only the memory specified by the SizeOfStackCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached. */
	protected int SizeOfStackReserve;
	/** The number of bytes to commit for the stack. */
	protected int SizeOfStackCommit;
	/** The number of bytes to reserve for the local heap. Only the memory specified by the SizeOfHeapCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached. */
	protected int SizeOfHeapReserve;
	/** The number of bytes to commit for the local heap. */
	protected int SizeOfHeapCommit;
	/** This member is obsolete. */
	protected int LoaderFlags;
	/** The number of directory entries in the remainder of the optional header. Each entry describes a location and size. */
	protected int NumberOfRvaAndSizes;
	
	/** The amount of directories */
	public static final int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
	
	/** Export Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_EXPORT         = 0;   // Export Directory
	/** Import Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_IMPORT         = 1;   // Import Directory
	/** Resource Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2;   // Resource Directory
	/** Exception Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3;   // Exception Directory
	/** Security Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_SECURITY       = 4;   // Security Directory
	/** Base Relocation Table */
	public static final int IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5;   // Base Relocation Table
	/** Debug Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_DEBUG          = 6;   // Debug Directory
	/**  (X86 usage) */
	public static final int IMAGE_DIRECTORY_ENTRY_COPYRIGHT      = 7;   // (X86 usage)
	/** Architecture Specific Data */
	public static final int IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7;   // Architecture Specific Data
	/** RVA of Global Pointer */
	public static final int IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8;   // RVA of GP
	/** Thread Local Storage Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_TLS            = 9;   // TLS Directory
	/** Load Configuration Directory */
	public static final int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10;  // Load Configuration Directory
	/** Bound Import Directory in headers */
	public static final int IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11;  // Bound Import Directory in headers
	/**  Import Address Table */
	public static final int IMAGE_DIRECTORY_ENTRY_IAT            = 12;  // Import Address Table
	/** Delay Load Import Descriptors */
	public static final int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13;  // Delay Load Import Descriptors
	/** COM Runtime descriptor */
	public static final int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;  // COM Runtime descriptor
	
	/** A pointer to the first IMAGE_DATA_DIRECTORY structure in the data directory. */
	protected IMAGE_DATA_DIRECTORY DataDirectory[];
	/** An array containing the objects trying to abstract the directories. */
	protected Object       DirectoryEntries[];
	
	
    /**
     * Parse a IMAGE_OPTIONAL_HEADER32 at the current reader position
     * @param reader the reader containing the binary data to parse
     * @throws Exception something went wrong
     */
	public IMAGE_OPTIONAL_HEADER32(ExecutableReader reader)
			throws Exception {
		super(reader);
	}
	
	@Override
	public void read(ExecutableStream s) throws Exception {
		DataDirectory = new IMAGE_DATA_DIRECTORY[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		DirectoryEntries = new Object[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		Magic = s.readAddrShort();
		MajorLinkerVersion = s.readAddrByte();
		MinorLinkerVersion = s.readAddrByte();
		SizeOfCode = s.readAddrInt();
		SizeOfInitializedData = s.readAddrInt();
		SizeOfUninitializedData = s.readAddrInt();
		AddressOfEntryPoint = s.readAddrInt();
		BaseOfCode = s.readAddrInt();
		BaseOfData = s.readAddrInt();
		ImageBase = s.readAddrInt();
		SectionAlignment = s.readAddrInt();
		FileAlignment = s.readAddrInt();
		MajorOperatingSystemVersion = s.readAddrShort();
		MinorOperatingSystemVersion = s.readAddrShort();
		MajorImageVersion = s.readAddrShort();
		MinorImageVersion = s.readAddrShort();
		MajorSubsystemVersion = s.readAddrShort();
		MinorSubsystemVersion = s.readAddrShort();
		Reserved1 = s.readAddrInt();
		SizeOfImage = s.readAddrInt();
		SizeOfHeaders = s.readAddrInt();
		CheckSum = s.readAddrInt();
		Subsystem = s.readAddrShort();
		DllCharacteristics = s.readAddrShort();
		SizeOfStackReserve = s.readAddrInt();
		SizeOfStackCommit = s.readAddrInt();
		SizeOfHeapReserve = s.readAddrInt();
		SizeOfHeapCommit = s.readAddrInt();
		LoaderFlags = s.readAddrInt();
		NumberOfRvaAndSizes = s.readAddrInt();
		for (int i = 0; i < DataDirectory.length; i++)
			DataDirectory[i] = new IMAGE_DATA_DIRECTORY(reader);
	}
	
	/**
	 * Dump the Import Table (not the Hint Table) to stdout
	 */
	public void printImportTable() {
		//Exit if no import table is found
		if(DirectoryEntries[IMAGE_DIRECTORY_ENTRY_IMPORT] == null) {
			System.out.println("[*] No Import Table Entry found");
			return;
		}
		System.out.println("[*] Dumping Imports:");
		for(IMAGE_IMPORT_DESCRIPTOR desc:getImportDescriptor().getImports()) {
			try {
				System.out.println(desc.getDLLName()+":");
				IMAGE_THUNK_DATA[] thunks = desc.parseImportTable();
				//Dump THUNK_DATA[] for the current DLL
				for(IMAGE_THUNK_DATA thunk:thunks) {
					//Print out the Ordinal OR the name depending on the value within the THUNK_DATA
					if(thunk.isOrdinal())
						System.out.println("   Ordinal: "+thunk.getOrdinal());
					else
						System.out.println("   Name:    "+thunk.getName());
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	
	/**
	 * Dump the Resource Table to stdout
	 */
	public void printResourceTable() {
		//Exit if no resource table is found
		if(DirectoryEntries[IMAGE_DIRECTORY_ENTRY_RESOURCE] == null) {
			System.out.println("[*] No Resource Table Entry found");
			return;
		}
		System.out.println("[*] Dumping Resource Structure:");
		DescriptorResource res = getResourceDescriptor();
		printResourceDirectory(res.getRoot(), 0);
	}
	private void printResourceDirectory(IMAGE_RESOURCE_DIRECTORY dir, int lvl) {
		String prefix = "";
		for(int i=0;i<lvl;i++) prefix = prefix + " ";
		System.out.println(prefix+"NumberOfEntries: "+dir.getNumberOfEntries());
		for(IMAGE_RESOURCE_DIRECTORY_ENTRY entry:dir.getEntires()) {
			if(entry.isOrdinal())
				System.out.println(prefix+" ID:   "+entry.getID());
			else
				System.out.println(prefix+" Name: "+entry.getNameStr());
			if(entry.isDirectory()) {
				printResourceDirectory(entry.getDir(), lvl+1);
			}else {
				System.out.println(prefix+"  Size: "+entry.getData().getSize());
			}
		}
	}
	
	
	/**
	 * Dump the TLS (Thread Local Storage) to stdout
	 */
	public void printTLS() {
		//Exit if no import table is found
		if(DirectoryEntries[IMAGE_DIRECTORY_ENTRY_TLS] == null) {
			System.out.println("[*] No Thread Local Storage found");
			return;
		}
		System.out.println("[*] Dumping TLS:");
		System.out.println("   Size of "+(getTLSDescriptor().getTLS().getEndAddressOfRawData().getAddr64()-getTLSDescriptor().getTLS().getStartAddressOfRawData().getAddr64())+ " bytes");
		if(getTLSDescriptor().getTLSCallbacks().length == 0)
			System.out.println("   No Callbacks");
		else {
			System.out.println("   Following Callbacks are present:");
			for(int i=0;i<getTLSDescriptor().getTLSCallbacks().length;i++)
				if(reader.is32bit())
					System.out.println("      "+(i+1)+". at 0x"+Integer.toHexString(getTLSDescriptor().getTLSCallbacks()[i].getAddr32()));
				else
					System.out.println("      "+(i+1)+". at 0x"+Long.toHexString(getTLSDescriptor().getTLSCallbacks()[i].getAddr64()));
		}
	}
	
	/**
	 * Return the IMAGE_DATA_DIRECTORY array
	 * @return the data directory array
	 */
	public IMAGE_DATA_DIRECTORY[] getDataDirectory() {
		return DataDirectory;
	}
	
	/**
	 * Return the abstract Import Directory Object if existent, else null
 	 * @return the abstract import directory
	 */
	public DescriptorImport getImportDescriptor() {
		return (DescriptorImport) DirectoryEntries[IMAGE_DIRECTORY_ENTRY_IMPORT];
	}
	
	/**
	 * Return the abstract Resource Directory Object if existent, else null
 	 * @return the abstract resource directory
	 */
	public DescriptorResource getResourceDescriptor() {
		return (DescriptorResource) DirectoryEntries[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	}
	
	/**
	 * Return the abstract TLS Directory Object if existent, else null
 	 * @return the abstract TLS directory
	 */
	public DescriptorTLS getTLSDescriptor() {
		return (DescriptorTLS) DirectoryEntries[IMAGE_DIRECTORY_ENTRY_TLS];
	}
	
	/**
	 * Return the array of abstract directory objects
	 * @return the array of abstract directory objects
	 */
	public Object[] getDirectoryEntries() {
		return DirectoryEntries;
	}
	
	/**
	 * Offset for reading the resources the correct way
	 * @return file offset to resources if they exist (0 if not)
	 */
	public int getResourceOffset() {
		return reader.rva2offset(new Address(getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_RESOURCE].getVirtualAddress()));
	}
	
	/**
	 * Return whether this is the IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64
	 * @return if this is the 32bit or 64bit version
	 */
	public boolean is32bit() { return true; }

	/**
	 * Parse Directories of the PE File <br>
	 * Current Implemented: ImportTable, ResourceTable<br>
	 * NOTE: NOT THREAD SAFE
	 * @throws Exception Something went wrong while parsing
	 */
	public void parseDirectories() {
		parseImportTable();
		parseResourceTable();
		parseTLS();
	}
	
	/**
	 * Parse the import directory
	 */
	public void parseImportTable() {
		int temp = reader.getStream().getIndex();	
		try {
			//IMPORT DIRECTORY
			Address rva = new Address(getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IMPORT].getVirtualAddress());
			
			if(!rva.isNull()) {
				reader.getStream().setIndex(reader.rva2offset(rva));
				DirectoryEntries[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_IMPORT] = new DescriptorImport(reader);
			}
		}catch(Exception e) {
			e.printStackTrace();
			System.err.println("Failed Reading Import Table");
		}	
		//Restore reader
		reader.getStream().setIndex(temp);
	}
	
	/**
	 * Parse the resource directory
	 */
	public void parseResourceTable() {
		int temp = reader.getStream().getIndex();	
		try {
			//RESOURCE DIRECTORY
			Address rva = new Address(getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_RESOURCE].getVirtualAddress());
			if(!rva.isNull()) {
				reader.getStream().setIndex(reader.rva2offset(rva));
				DirectoryEntries[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_RESOURCE] = new DescriptorResource(reader);
			}
		}catch(Exception e) {
			e.printStackTrace();
			System.err.println("Failed Reading Resource Table");
		}	
		//Restore reader
		reader.getStream().setIndex(temp);
	}
	
	/**
	 * Parse the TLS directory
	 */
	public void parseTLS() {
		int temp = reader.getStream().getIndex();	
		try {
			//IMPORT DIRECTORY
			Address rva = new Address(getDataDirectory()[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_TLS].getVirtualAddress());
			
			if(!rva.isNull()) {
				reader.getStream().setIndex(reader.rva2offset(rva));
				DirectoryEntries[IMAGE_OPTIONAL_HEADER32.IMAGE_DIRECTORY_ENTRY_TLS] = new DescriptorTLS(reader);
			}
		}catch(Exception e) {
			e.printStackTrace();
			System.err.println("Failed Reading TLS Table");
		}	
		//Restore reader
		reader.getStream().setIndex(temp);
	}
	
	/**
	 * Return the state of this image file. (Indicating what this file is)
	 * @return the state of this image file
	 */
	public short getMagic() {
		try {
			return reader.getStream().getShort(Magic);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the state of this image file
	 * @param magic the new state of this image file
	 */
	public void setMagic(short magic) {
		try {
			reader.getStream().setShort(Magic, magic);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the major version of the linker used
	 * @return the major linker version
	 */
	public char getMajorLinkerVersion() {
		try {
			return (char) reader.getStream().getByte(MajorLinkerVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the major version of the linker used
	 * @param majorLinkerVersion the new major linker version
	 */
	public void setMajorLinkerVersion(char majorLinkerVersion) {
		try {
			reader.getStream().setByte(MajorLinkerVersion,
					(byte) majorLinkerVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the minor version of the linker used
	 * @return the minor linker version
	 */
	public char getMinorLinkerVersion() {
		try {
			return (char) reader.getStream().getByte(MinorLinkerVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the minor version of the linker used
	 * @param minorLinkerVersion the new minor linker version
	 */
	public void setMinorLinkerVersion(char minorLinkerVersion) {
		try {
			reader.getStream().setByte(MinorLinkerVersion,
					(byte) minorLinkerVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the byte size of the code sections combined
	 * @return the size of all code sections added together
	 */
	public int getSizeOfCode() {
		try {
			return reader.getStream().getInt(SizeOfCode);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the byte size of all the code sections combined
	 * @param sizeOfCode the new size of all code sections added together
	 */
	public void setSizeOfCode(int sizeOfCode) {
		try {
			reader.getStream().setInt(SizeOfCode, sizeOfCode);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the byte size of the initialized data sections combined
	 * @return the size of all initialized data sections added together
	 */
	public int getSizeOfInitializedData() {
		try {
			return reader.getStream().getInt(SizeOfInitializedData);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the byte size of all the initialized data sections combined
	 * @param sizeOfInitializedData the new size of all initialized data sections added together
	 */
	public void setSizeOfInitializedData(int sizeOfInitializedData) {
		try {
			reader.getStream().setInt(SizeOfInitializedData, sizeOfInitializedData);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the byte size of the uninitialized data sections combined
	 * @return the size of all uninitialized data sections added together
	 */
	public int getSizeOfUninitializedData() {
		try {
			return reader.getStream().getInt(SizeOfUninitializedData);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the byte size of all the uninitialized data sections combined
	 * @param sizeOfUninitializedData the new size of all uninitialized data sections added together
	 */
	public void setSizeOfUninitializedData(int sizeOfUninitializedData) {
		try {
			reader.getStream().setInt(SizeOfUninitializedData,
					sizeOfUninitializedData);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the address of the entry point relative to the image base
	 * @return the address of the entry point
	 */
	public int getAddressOfEntryPoint() {
		try {
			return reader.getStream().getInt(AddressOfEntryPoint);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the address of the entry point relative to the image base
	 * @param addressOfEntryPoint the new entry point
	 */
	public void setAddressOfEntryPoint(int addressOfEntryPoint) {
		try {
			reader.getStream().setInt(AddressOfEntryPoint, addressOfEntryPoint);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the first address of the code sections relative to the image base
	 * @return the first address of the code sections
	 */
	public int getBaseOfCode() {
		try {
			return reader.getStream().getInt(BaseOfCode);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the first address of the code sections relative to the image base
	 * @param baseOfCode the new first address of the code sections
	 */
	public void setBaseOfCode(int baseOfCode) {
		try {
			reader.getStream().setInt(BaseOfCode, baseOfCode);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the first address of the data sections relative to the image base
	 * @return the first address of the data sections
	 */
	public int getBaseOfData() {
		try {
			return reader.getStream().getInt(BaseOfData);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the first address of the data sections relative to the image base
	 * @param baseOfData the new first address of the data sections
	 */
	public void setBaseOfData(int baseOfData) {
		try {
			reader.getStream().setInt(BaseOfData, baseOfData);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * The preferred address of the first byte of the image when loaded in memory
	 * <br>NOTE: On 64bit this only contains the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#getImageBase64()} instead
	 * @return the preferred address to load the image at
	 */
	public int getImageBase() {
		try {
			return reader.getStream().getInt(ImageBase);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the preferred address of the first byte of the image when loaded in memory
	 * <br>NOTE: On 64bit this only sets the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#setImageBase64(long)} instead
	 * @param imageBase the new preferred address to load the image at
	 */
	public void setImageBase(int imageBase) {
		try {
			reader.getStream().setInt(ImageBase, imageBase);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the alignment of sections in memory
	 * @return the alignment of sections in memory
	 */
	public int getSectionAlignment() {
		try {
			return reader.getStream().getInt(SectionAlignment);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the alignment of sections in memory, must be greater than the File Alignment 
	 * @param sectionAlignment the new alignment of sections in memory
	 */
	public void setSectionAlignment(int sectionAlignment) {
		try {
			reader.getStream().setInt(SectionAlignment, sectionAlignment);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the alignment of sections in the file as raw data
	 * @return the raw data section alignment
	 */
	public int getFileAlignment() {
		try {
			return reader.getStream().getInt(FileAlignment);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the alignment of sections in the file as raw data, must be a power of 2 between 512 and 64k
	 * @param fileAlignment
	 */
	public void setFileAlignment(int fileAlignment) {
		try {
			reader.getStream().setInt(FileAlignment, fileAlignment);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the major operating system version required to run this
	 * @return the major operating system version
	 */
	public short getMajorOperatingSystemVersion() {
		try {
			return reader.getStream().getShort(MajorOperatingSystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the major operation system version required to run this
	 * @param majorOperatingSystemVersion the new major operating system version
	 */
	public void setMajorOperatingSystemVersion(short majorOperatingSystemVersion) {
		try {
			reader.getStream().setShort(MajorOperatingSystemVersion,
					majorOperatingSystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the minor operating system version required to run this
	 * @return the minor operating system version
	 */
	public short getMinorOperatingSystemVersion() {
		try {
			return reader.getStream().getShort(MinorOperatingSystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the minor operation system version required to run this
	 * @param minorOperatingSystemVersion the new minor operating system version
	 */
	public void setMinorOperatingSystemVersion(short minorOperatingSystemVersion) {
		try {
			reader.getStream().setShort(MinorOperatingSystemVersion,
					minorOperatingSystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the major version of this image
	 * @return the major image version
	 */
	public short getMajorImageVersion() {
		try {
			return reader.getStream().getShort(MajorImageVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the major version of this image
	 * @param majorImageVersion the new major image version
	 */
	public void setMajorImageVersion(short majorImageVersion) {
		try {
			reader.getStream().setShort(MajorImageVersion, majorImageVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the minor version of this image
	 * @return the minor image version
	 */
	public short getMinorImageVersion() {
		try {
			return reader.getStream().getShort(MinorImageVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the minor version of this image
	 * @param minorImageVersion the new minor image version
	 */
	public void setMinorImageVersion(short minorImageVersion) {
		try {
			reader.getStream().setShort(MinorImageVersion, minorImageVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the required major version of the subsystem used
	 * @return the major subsystem version
	 */
	public short getMajorSubsystemVersion() {
		try {
			return reader.getStream().getShort(MajorSubsystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the required major version of the subsystem used
	 * @param majorSubsystemVersion the new required major subsystem version
	 */
	public void setMajorSubsystemVersion(short majorSubsystemVersion) {
		try {
			reader.getStream().setShort(MajorSubsystemVersion,
					majorSubsystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the required minor version of the subsystem used
	 * @return the minor subsystem version
	 */
	public short getMinorSubsystemVersion() {
		try {
			return reader.getStream().getShort(MinorSubsystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the required minor version of the subsystem used
	 * @param majorSubsystemVersion the new required minor subsystem version
	 */
	public void setMinorSubsystemVersion(short minorSubsystemVersion) {
		try {
			reader.getStream().setShort(MinorSubsystemVersion,
					minorSubsystemVersion);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the value at the Reversed1 field
	 * @return the value at the Reserved1 field
	 */
	public int getReserved1() {
		try {
			return reader.getStream().getInt(Reserved1);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the value at the Reserved1 field, should be 0
	 * @param reserved1 the new value at the Reserved1 field
	 */
	public void setReserved1(int reserved1) {
		try {
			reader.getStream().setInt(Reserved1, reserved1);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the size of the image including all headers, must be multiple of the Section Alignment
	 * @return the size of the image
	 */
	public int getSizeOfImage() {
		try {
			return reader.getStream().getInt(SizeOfImage);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the size of the image including all headers, must be multiple of the Section Alignment
	 * @param sizeOfImage the new size of the image
	 */
	public void setSizeOfImage(int sizeOfImage) {
		try {
			reader.getStream().setInt(SizeOfImage, sizeOfImage);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the size of the headers, rounded up multiple of FileAlignment
	 * @return the size of the headers
	 */
	public int getSizeOfHeaders() {
		try {
			return reader.getStream().getInt(SizeOfHeaders);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	/**
	 * Set the size of the header, rounded up multiple of FileAlignment.
	 * The size of headers consists out of the following elements: e_lfanew member of IMAGE_DOS_HEADER, 4 byte signature, size of IMAGE_FILE_HEADER, size of optional header, size of all section headers
	 * @param sizeOfHeaders
	 */
	public void setSizeOfHeaders(int sizeOfHeaders) {
		try {
			reader.getStream().setInt(SizeOfHeaders, sizeOfHeaders);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the checksum of this image file
	 * @return the checksum
	 */
	public int getCheckSum() {
		try {
			return reader.getStream().getInt(CheckSum);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the checksum of this image file
	 * @param checkSum the new checksum
	 */
	public void setCheckSum(int checkSum) {
		try {
			reader.getStream().setInt(CheckSum, checkSum);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the subsystem this image file is meant to run on.
	 * @return the subsystem of this image file
	 */
	public short getSubsystem() {
		try {
			return reader.getStream().getShort(Subsystem);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the subsystem of this image file
	 * @param subsystem the new subsystem
	 */
	public void setSubsystem(short subsystem) {
		try {
			reader.getStream().setShort(Subsystem, subsystem);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the DLL Characteristics of this image file.
	 * @return the DLL Characteristics
	 */
	public short getDllCharacteristics() {
		try {
			return reader.getStream().getShort(DllCharacteristics);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the DLL Characteristics of this image file.
	 * @param dllCharacteristics the new DLL Characteristics
	 */
	public void setDllCharacteristics(short dllCharacteristics) {
		try {
			reader.getStream().setShort(DllCharacteristics, dllCharacteristics);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the amount of bytes reserved for the stack of this image file
	 * <br>NOTE: On 64bit this only contains the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#getSizeOfStackReserve64()} instead
	 * @return the amount of bytes reserved for the stack
	 */
	public int getSizeOfStackReserve() {
		try {
			return reader.getStream().getInt(SizeOfStackReserve);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the amount of bytes reserved for the stack of this image file
	 * <br>NOTE: On 64bit this only sets the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#setSizeOfStackReserve64(long)} instead
	 * @param sizeOfStackReserve the new amount of bytes reserved for the stack
	 */
	public void setSizeOfStackReserve(int sizeOfStackReserve) {
		try {
			reader.getStream().setInt(SizeOfStackReserve, sizeOfStackReserve);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the amount of bytes committed to the stack at load time
	 * <br>NOTE: On 64bit this only contains the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#getSizeOfStackCommit64()} instead
	 * @return the amount of bytes initially committed to the stack
	 */
	public int getSizeOfStackCommit() {
		try {
			return reader.getStream().getInt(SizeOfStackCommit);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the amount of bytes committed to the stack at load time
	 * <br>NOTE: On 64bit this only sets the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#setSizeOfStackCommit64(long)} instead
	 * @param sizeOfStackCommit  the new amount of bytes initially committed to the stack
	 */
	public void setSizeOfStackCommit(int sizeOfStackCommit) {
		try {
			reader.getStream().setInt(SizeOfStackCommit, sizeOfStackCommit);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}


	/**
	 * Return the amount of bytes reserved for the heap of this image file
	 * <br>NOTE: On 64bit this only contains the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#getSizeOfHeapReserve64()} instead
	 * @return the amount of bytes reserved for the heap
	 */
	public int getSizeOfHeapReserve() {
		try {
			return reader.getStream().getInt(SizeOfHeapReserve);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the amount of bytes reserved for the heap of this image file
	 * <br>NOTE: On 64bit this only sets the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#setSizeOfHeapReserve64(long)} instead
	 * @param sizeOfHeapReserve the new amount of bytes reserved for the heap
	 */
	public void setSizeOfHeapReserve(int sizeOfHeapReserve) {
		try {
			reader.getStream().setInt(SizeOfHeapReserve, sizeOfHeapReserve);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the amount of bytes committed to the heap at load time
	 * <br>NOTE: On 64bit this only contains the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#getSizeOfHeapCommit64()} instead
	 * @return the amount of bytes initially committed to the heap
	 */
	public int getSizeOfHeapCommit() {
		try {
			return reader.getStream().getInt(SizeOfHeapCommit);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the amount of bytes committed to the heap at load time
	 * <br>NOTE: On 64bit this only sets the lower 32bit, use {@link IMAGE_OPTIONAL_HEADER64#setSizeOfHeapCommit64(long)} instead
	 * @param sizeOfHeapCommit  the new amount of bytes initially committed to the heap
	 */
	public void setSizeOfHeapCommit(int sizeOfHeapCommit) {
		try {
			reader.getStream().setInt(SizeOfHeapCommit, sizeOfHeapCommit);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the loader flags of this image, this field is obsolete.
	 * @return the loader flags
	 */
	public int getLoaderFlags() {
		try {
			return reader.getStream().getInt(LoaderFlags);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the loader flags of this image, this field is obsolete.
	 * @param loaderFlags the new loader flags
	 */
	public void setLoaderFlags(int loaderFlags) {
		try {
			reader.getStream().setInt(LoaderFlags, loaderFlags);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the amount of following directory entries
	 * @return the amount of directory entries
	 */
	public int getNumberOfRvaAndSizes() {
		try {
			return reader.getStream().getInt(NumberOfRvaAndSizes);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the amount of following directory entries
	 * @param numberOfRvaAndSizes the new amount of directory entries
	 */
	public void setNumberOfRvaAndSizes(int numberOfRvaAndSizes) {
		try {
			reader.getStream().setInt(NumberOfRvaAndSizes, numberOfRvaAndSizes);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the name of the subsystem this image file is meant to run on as a string
	 * @return the name of the subsystem of this image file
	 */
	public String getSubsystemString() {
		switch (getSubsystem()) {
		case 0x0:
			return "IMAGE_SUBSYSTEM_UNKNOWN";
		case 0x1:
			return "IMAGE_SUBSYSTEM_NATIVE";
		case 0x2:
			return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
		case 0x3:
			return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
		case 0x7:
			return "IMAGE_SUBSYSTEM_POSIX_CUI";
		case 0x9:
			return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
		case 0x10:
			return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
		case 0x11:
			return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
		case 0x12:
			return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
		case 0x13:
			return "IMAGE_SUBSYSTEM_EFI_ROM";
		case 0x14:
			return "IMAGE_SUBSYSTEM_XBOX";
		default:
			return "@Error "+Integer.toHexString(getSubsystem());
		}
	}

/**
 * A class representing the IMAGE_DATA_DIRECTORY structure in a given binary reader.
*/
public static class IMAGE_DATA_DIRECTORY extends ReadableObject{
	
	/** The RVA to the directory entry */
	protected int VirtualAddress;
	
	/** The size of the directory entry in bytes */
	protected int Size;

    /**
     * Parse a IMAGE_DATA_DIRECTORY at the current reader position
     * @param reader the reader containing the binary data to parse
     * @throws Exception something went wrong
     */
	public IMAGE_DATA_DIRECTORY(ExecutableReader reader)
			throws Exception {
		super(reader);
	}

	@Override
	public void read(ExecutableStream s) throws Exception {
		VirtualAddress = s.readAddrInt();
		Size = s.readAddrInt();
	}

	/**
	 * Return the relative virtual address this directory entry is positioned at
	 * @return the RVA of the directory entry
	 */
	public int getVirtualAddress() {
		try {
			return reader.getStream().getInt(VirtualAddress);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the relative virtual address this directory entry is positioned at
	 * @param virtualAddress the new RVA of the directory entry
	 */
	public void setVirtualAddresss(int virtualAddress) {
		try {
			reader.getStream().setInt(VirtualAddress, virtualAddress);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the size of the directory entry in bytes
	 * @return the size of the directory entry
	 */
	public int getSize() {
		try {
			return reader.getStream().getInt(Size);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the size of the directory entry in bytes
	 * @param size the new size of the directory entry
	 */
	public void setSize(int size) {
		try {
			reader.getStream().setInt(Size, size);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	
}



}