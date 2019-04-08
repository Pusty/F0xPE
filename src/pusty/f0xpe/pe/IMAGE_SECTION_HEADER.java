package pusty.f0xpe.pe;

import java.io.IOException;
import java.util.ArrayList;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.pe.ExecutableReader;

/**
 * A class representing the IMAGE_SECTION_HEADER structure in a given binary reader.
 * <br>Reference: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_section_header
 * <br>Header: winnt.h
 */
public class IMAGE_SECTION_HEADER extends ReadableObject {
	
	/** The constant size of section header names */
	public static final int IMAGE_SIZEOF_SHORT_NAME = 8;
	
	/** The section can be executed as code.  */
	public static final int IMAGE_SCN_MEM_EXECUTE = 0x20000000;
	/** The section can be read. */
	public static final int IMAGE_SCN_MEM_READ = 0x40000000;
	/** The section can be written to. */
	public static final int IMAGE_SCN_MEM_WRITE = 0x80000000;
	/** The section can be shared in memory. */
	public static final int IMAGE_SCN_MEM_SHARED = 0x10000000;	
	/** The section contains uninitialized data. */
	public static final int IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
	/** The section contains initialized data. */
	public static final int IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
	/** The section contains executable code. */
	public static final int IMAGE_SCN_CNT_CODE = 0x00000020;
	/** The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. */
	public static final int IMAGE_SCN_TYPE_NO_PAD = 0x00000020;
	
	
	//The descriptions of these fields are copy pasted from the Microsoft documentation
	
	/** An 8-byte, null-padded UTF-8 string. There is no terminating null character if the string is exactly eight characters long.  */
    protected int[] NameData; //BYTE[IMAGE_SIZEOF_SHORT_NAME]
    /** The total size of the section when loaded into memory, in bytes. If this value is greater than the SizeOfRawData member, the section is filled with zeroes. This field is valid only for executable images and should be set to 0 for object files. */
    protected int VirtualSize; //union {DWORD PhysicalAddress;DWORD VirtualSize;} 
    /** The address of the first byte of the section when loaded into memory, relative to the image base. For object files, this is the address of the first byte before relocation is applied. */
    protected int VirtualAddress; //DWORD 
    /** The size of the initialized data on disk, in bytes. This value must be a multiple of the FileAlignment member of the IMAGE_OPTIONAL_HEADER structure. If this value is less than the VirtualSize member, the remainder of the section is filled with zeroes. If the section contains only uninitialized data, the member is zero.*/
    protected int SizeOfRawData; //DWORD 
    /** A file pointer to the first page within the COFF file. This value must be a multiple of the FileAlignment member of the IMAGE_OPTIONAL_HEADER structure. If a section contains only uninitialized data, set this member is zero. */
    protected int PointerToRawData; //DWORD 
    /** A file pointer to the beginning of the relocation entries for the section. If there are no relocations, this value is zero. */
    protected int PointerToRelocations; //DWORD 
    /** A file pointer to the beginning of the line-number entries for the section. If there are no COFF line numbers, this value is zero. */
    protected int PointerToLinenumbers; //DWORD 
    /** The number of relocation entries for the section. This value is zero for executable images. */
    protected int NumberOfRelocations; //WORD  
    /** The number of line-number entries for the section. */
    protected int NumberOfLinenumbers; //WORD  
    /** The characteristics of the image. */
    protected int Characteristics; //DWORD 

    /**
     * Parse a IMAGE_SECTION_HEADER at the current reader position
     * @param reader the reader containing the binary data to parse
     * @throws Exception something went wrong
     */
	public IMAGE_SECTION_HEADER(ExecutableReader reader) throws Exception {
		super(reader);
	}
	
	@Override
	public void read(ExecutableStream s) throws Exception {
		NameData = new int[IMAGE_SIZEOF_SHORT_NAME];
		for(int i=0;i<NameData.length;i++)
			NameData[i] = s.readAddrByte();
		VirtualSize = s.readAddrInt();
		VirtualAddress = s.readAddrInt();
		SizeOfRawData = s.readAddrInt();
		PointerToRawData = s.readAddrInt();
		PointerToRelocations = s.readAddrInt();
		PointerToLinenumbers = s.readAddrInt();
		NumberOfRelocations = s.readAddrShort();
		NumberOfLinenumbers = s.readAddrShort();
		Characteristics = s.readAddrInt();

	}
	
	/**
	 * Return the bytes of the section name read from the stream
	 * @return the name of the section as a byte array, null on error
	 */
	public byte[] getNameData() {
		try {
			byte[] output = new byte[this.NameData.length];
			for(int i=0;i<this.NameData.length;i++)
				output[i] = reader.getStream().getByte(this.NameData[i]);
			return output;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Set the bytes of the name within the stream
	 * @param nameData the new name of this section
	 */
	public void setNameData(byte[] nameData) {
		try {
			for(int i=0;i<this.NameData.length;i++)
				reader.getStream().setByte(this.NameData[i], nameData[i]);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the size this section has when loaded into memory.
	 * Everything outside of the SizeOfRawData will be 0 filled
	 * @return the size of the virtual memory of this section
	 */
	public int getVirtualSize() {
		try {
			return reader.getStream().getInt(VirtualSize);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the size of this section in loaded memory
	 * @param virtualSize the new virtual size of this section
	 */
	public void setVirtualSize(int virtualSize) {
		try {
			reader.getStream().setInt(VirtualSize, virtualSize);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the address of the first byte in virtual memory, relative to the image base.
	 * @return the first relative virtual address of this section
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
	 * Set the virtual address of this section
	 * @param virtualAddress the first address of this section relative to the image base
	 */
	public void setVirtualAddress(int virtualAddress) {
		try {
			reader.getStream().setInt(VirtualAddress, virtualAddress);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the size of this section within the file, must be a multiple of IMAGE_OPTIONAL_HEADER.FileAlignment 
	 * @return the size of this section with in the PE file
	 */
	public int getSizeOfRawData() {
		try {
			return reader.getStream().getInt(SizeOfRawData);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the size of this section within the file/stream
	 * @param sizeOfRawData the new size of this section, must be a multiple of IMAGE_OPTIONAL_HEADER.FileAlignment 
	 */
	public void setSizeOfRawData(int sizeOfRawData) {
		try {
			reader.getStream().setInt(SizeOfRawData, sizeOfRawData);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the pointer to the raw data of this section within the file starting at the COFF Header
	 * @return the pointer to the data in the file/stream
	 */
	public int getPointerToRawData() {
		try {
			return reader.getStream().getInt(PointerToRawData);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the pointer to the raw data starting at the COFF Header
	 * @param pointerToRawData the offset from the COFF Header to the data of this section
	 */
	public void setPointerToRawData(int pointerToRawData) {
		try {
			reader.getStream().setInt(PointerToRawData, pointerToRawData);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the pointer to the beginning of the relocation entries for this section. 0 if not existent
	 * @return the pointer to relocation entries for this section
	 */
	public int getPointerToRelocations() {
		try {
			return reader.getStream().getInt(PointerToRelocations);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the pointer of the relocation entries for this section. 0 if not existent
	 * @param pointerToRelocations the new pointer for the relocation entries
	 */
	public void setPointerToRelocations(int pointerToRelocations) {
		try {
			reader.getStream().setInt(PointerToRelocations, pointerToRelocations);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the pointer to the line numbers, Probably 0
	 * @return the pointer to the line numbers of this section
	 */
	public int getPointerToLinenumbers() {
		try {
			return reader.getStream().getInt(PointerToLinenumbers);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the line number pointer for this section.
	 * @param pointerToLinenumbers the new pointer to line numbers
	 */
	public void setPointerToLinenumbers(int pointerToLinenumbers) {
		try {
			reader.getStream().setInt(PointerToLinenumbers, pointerToLinenumbers);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the number of relocations for this section. 0 for executable files
	 * @return the amount of relocations
	 */
	public short getNumberOfRelocations() {
		try {
			return reader.getStream().getShort(NumberOfRelocations);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the number of relocations for this section. Should be 0 for executable files
	 * @param numberOfRelocations the new amount of relocation entries
	 */
	public void setNumberOfRelocations(short numberOfRelocations) {
		try {
			reader.getStream().setShort(NumberOfRelocations, numberOfRelocations);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the number of LineNumber entries for this section, probably 0
	 * @return the amount of line numbers
	 */
	public short getNumberOfLinenumbers() {
		try {
			return reader.getStream().getShort(NumberOfLinenumbers);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the number of LineNumber entries for this section
	 * @param numberOfLinenumbers the new amount of line numbers
	 */
	public void setNumberOfLinenumbers(short numberOfLinenumbers) {
		try {
			reader.getStream().setShort(NumberOfLinenumbers, numberOfLinenumbers);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the Characteristics of this section, more info at the IMAGE_SCN_* constants
	 * @return the characteristics of this section determining its behavior
	 */
	public int getCharacteristics() {
		try {
			return reader.getStream().getInt(Characteristics);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the Characteristics of this section, more info at the IMAGE_SCN_* constants
	 * @param characteristics the new characteristics of this section
	 */
	public void setCharacteristics(int characteristics) {
		try {
			reader.getStream().setInt(Characteristics, characteristics);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	
	/**
	 * A helper function to present all characteristics of this section as an ArrayList of strings
	 * @return an ArrayList containing all characteristics of this section
	 */
	public ArrayList<String> printCharacteristics() {
		ArrayList<String> list = new ArrayList<String>();
		int temp = getCharacteristics();
		if ((temp & IMAGE_SCN_MEM_EXECUTE) != 0)
			list.add("IMAGE_SCN_MEM_EXECUTE");
		if ((temp & IMAGE_SCN_MEM_READ) != 0)
			list.add("IMAGE_SCN_MEM_READ");
		if ((temp & IMAGE_SCN_MEM_WRITE) != 0)
			list.add("IMAGE_SCN_MEM_WRITE");
		if ((temp & IMAGE_SCN_MEM_SHARED) != 0)
			list.add("IMAGE_SCN_MEM_SHARED");
		if ((temp & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
			list.add("IMAGE_SCN_CNT_UNINITIALIZED_DATA");
		if ((temp & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
			list.add("IMAGE_SCN_CNT_INITIALIZED_DATA");
		if ((temp & IMAGE_SCN_TYPE_NO_PAD) != 0)
			list.add("IMAGE_SCN_TYPE_NO_PAD");
		if ((temp & IMAGE_SCN_CNT_CODE) != 0)
			list.add("IMAGE_SCN_CNT_CODE");
		//MAYBE ADD MORE IF NEEDED
		return list;
	}

	/**
	 * Return the name of this section as a string
	 * @return the name of this section as a string
	 */
	public String getName() {
		return new String(getNameData());
	}
	
	/**
	 * Set the name of this section by supplying a string, everything over the IMAGE_SIZEOF_SHORT_NAME size will be ignored, everything less will be padded with 0 bytes
	 * @param name the new name of this section
	 */
	public void setName(String name) {
		byte[] data = new byte[IMAGE_SIZEOF_SHORT_NAME];
		for(int i=0;i<IMAGE_SIZEOF_SHORT_NAME;i++)
			data[i] = (byte) (i>=name.length()?0:name.charAt(i));
		this.setNameData(data);
	}
}
