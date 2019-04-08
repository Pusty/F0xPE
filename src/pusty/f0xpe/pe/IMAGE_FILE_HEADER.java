package pusty.f0xpe.pe;

import java.io.IOException;
import java.util.ArrayList;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.pe.ExecutableReader;

/**
 * A class representing the IMAGE_FILE_HEADER structure in a given binary reader.
 * <br>Reference: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_file_header
 * <br>Header: winnt.h
 */
public class IMAGE_FILE_HEADER extends ReadableObject {
	
	public static final short IMAGE_FILE_MACHINE_UNKNOWN = 0x0;
	public static final short IMAGE_FILE_MACHINE_ALPHA = 0x184;
	/** ARM little endian */
	public static final short IMAGE_FILE_MACHINE_ARM = 0x1c0;
	public static final short IMAGE_FILE_MACHINE_ALPHA64 = 0x284;
	/** Intel 386 or later processors and compatible processors */
	public static final short IMAGE_FILE_MACHINE_I386 = 0x14c;
	/** Intel Itanium processor family */
	public static final short IMAGE_FILE_MACHINE_IA64 = 0x200;
	public static final short IMAGE_FILE_MACHINE_M68K = 0x268; 
	/** MIPS16 */
	public static final short IMAGE_FILE_MACHINE_MIPS16 = 0x266;
	/** MIPS with FPU */
	public static final short IMAGE_FILE_MACHINE_MIPSFPU = 0x366;
	/** MIPS16 with FPU */
	public static final short IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466;
	/** Power PC little endian */
	public static final short IMAGE_FILE_MACHINE_POWERPC = 0x1f0;
	public static final short IMAGE_FILE_MACHINE_R3000 = 0x162;
	public static final short IMAGE_FILE_MACHINE_R4000 = 0x166;
	public static final short IMAGE_FILE_MACHINE_R10000 = 0x168;
	/** Hitachi SH3 */
	public static final short IMAGE_FILE_MACHINE_SH3 = 0x1a2;
	/** Hitachi SH4 */
	public static final short IMAGE_FILE_MACHINE_SH4 = 0x1a6;
	/** Thumb */
	public static final short IMAGE_FILE_MACHINE_THUMB = 0x1c2;
	/** x64 */
	public static final short IMAGE_FILE_MACHINE_AMD64 = (short) 0x8664;
	
	
	//The descriptions of these fields are copy pasted from the Microsoft documentation

	/** The architecture type of the computer. An image file can only be run on the specified computer or a system that emulates the specified computer. */
	protected int Machine;
	/** The number of sections. This indicates the size of the section table, which immediately follows the headers. Note that the Windows loader limits the number of sections to 96. */
	protected int NumberOfSections;
	/** The low 32 bits of the time stamp of the image. This represents the date and time the image was created by the linker. The value is represented in the number of seconds elapsed since midnight (00:00:00), January 1, 1970, Universal Coordinated Time, according to the system clock. */
	protected int TimeDateStamp;
	/** The offset of the symbol table, in bytes, or zero if no COFF symbol table exists. */
	protected int PointerToSymbolTable;
	/** The number of symbols in the symbol table. */
	protected int NumberOfSymbols;
	/** The size of the optional header, in bytes. */
	protected int SizeOfOptionalHeader;
	/** The characteristics of the image. */
	protected int Characteristics;


    /**
     * Parse a IMAGE_FILE_HEADER at the current reader position
     * @param reader the reader containing the binary data to parse
     * @throws Exception something went wrong
     */
	public IMAGE_FILE_HEADER(ExecutableReader reader)
			throws Exception {
		super(reader);
	}

	@Override
	public void read(ExecutableStream s) throws Exception {
		Machine = s.readAddrShort();
		NumberOfSections = s.readAddrShort();
		TimeDateStamp = s.readAddrInt();
		PointerToSymbolTable = s.readAddrInt();
		NumberOfSymbols = s.readAddrInt();
		SizeOfOptionalHeader = s.readAddrShort();
		Characteristics = s.readAddrShort();
	}

	/**
	 * Return the number of sections (the Windows loader limits this to 96)
	 * @return the amount of sections
	 */
	public short getNumberOfSections() {
		try {
			return reader.getStream().getShort(NumberOfSections);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the number of sections (the Windows loader limits this to 96)
	 * @param numberOfSections the new amount of sections
	 */
	public void setNumberOfSections(short numberOfSections) {
		try {
			reader.getStream().setShort(NumberOfSections, numberOfSections);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the time date stamp indicating the creation of this executable
	 * @return the time date stamp of this binary
	 */
	public int getTimeDateStamp() {
		try {
			return reader.getStream().getInt(TimeDateStamp);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the time date stamp indicating the creation of this executable
	 * @param timeDateStamp the new date time stamp of this binary
	 */
	public void setTimeDateStamp(int timeDateStamp) {
		try {
			reader.getStream().setInt(TimeDateStamp, timeDateStamp);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return an offset to the COFF symbol table of this executable if existent, else 0
	 * @return an offset to the symbol table if existent 
	 */
	public int getPointerToSymbolTable() {
		try {
			return reader.getStream().getInt(PointerToSymbolTable);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the offset to the COFF symbol table of this executable if existent, else 0
	 * @param pointerToSymbolTable the new offset to the symbol table if existent
	 */
	public void setPointerToSymbolTable(int pointerToSymbolTable) {
		try {
			reader.getStream().setInt(PointerToSymbolTable, pointerToSymbolTable);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the number of symbols in the COFF symbol table
	 * @return the amount of entries in the symbol table
	 */
	public int getNumberOfSymbols() {
		try {
			return reader.getStream().getInt(NumberOfSymbols);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the amount of symbols in the COFF symbol table
	 * @param numberOfSymbols the new amount of entries in the symbol table
	 */
	public void setNumberOfSymbols(int numberOfSymbols) {
		try {
			reader.getStream().setInt(NumberOfSymbols, numberOfSymbols);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the size of the IMAGE_OPTIONAL_HEADER of this executable in bytes
	 * @return the size in bytes of the Option Header
	 */
	public short getSizeOfOptionalHeader() {
		try {
			return reader.getStream().getShort(SizeOfOptionalHeader);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the size of the IMAGE_OPTIONAL_HEADER of this executable
	 * @param sizeOfOptionalHeader the new size inf bytes of the Optional Header
	 */
	public void setSizeOfOptionalHeader(short sizeOfOptionalHeader) {
		try {
			reader.getStream().setShort(SizeOfOptionalHeader, sizeOfOptionalHeader);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the characteristics of this file header
	 * @return the characteristics
	 */
	public short getCharacteristics() {
		try {
			return reader.getStream().getShort(Characteristics);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the characteristics of this file header
	 * @param characteristics the new characteristics
	 */
	public void setCharacteristics(short characteristics) {
		try {
			reader.getStream().setShort(Characteristics, characteristics);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the architecture this binary is intended to run on.
	 * @return the architecture of this executable
	 */
	public short getMachine() {
		try {
			return reader.getStream().getShort(Machine);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the architecture this binary is intended to run on.
	 * @param machine the new architecture of this executable
	 */
	public void setMachine(short machine) {
		try {
			reader.getStream().setShort(Machine, machine);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the name of the architecture this binary is intended to run on as a String
	 * @return the name of the intended machine type
	 */
	public String getMachineString() {
		switch (getMachine()) {
		case IMAGE_FILE_MACHINE_UNKNOWN:
			return "IMAGE_FILE_MACHINE_UNKNOWN";
		case IMAGE_FILE_MACHINE_ALPHA:
			return "IMAGE_FILE_MACHINE_ALPHA";
		case IMAGE_FILE_MACHINE_ARM:
			return "IMAGE_FILE_MACHINE_ARM"; /* ARM little endian */
		case IMAGE_FILE_MACHINE_ALPHA64:
			return "IMAGE_FILE_MACHINE_ALPHA64";
		case IMAGE_FILE_MACHINE_I386:
			return "IMAGE_FILE_MACHINE_I386"; /* Intel 386 or later processors and compatible processors */
		case IMAGE_FILE_MACHINE_IA64:
			return "IMAGE_FILE_MACHINE_IA64"; /* Intel Itanium processor family */
		case IMAGE_FILE_MACHINE_M68K:
			return "IMAGE_FILE_MACHINE_M68K";
		case IMAGE_FILE_MACHINE_MIPS16:
			return "IMAGE_FILE_MACHINE_MIPS16"; /* MIPS16 */
		case IMAGE_FILE_MACHINE_MIPSFPU:
			return "IMAGE_FILE_MACHINE_MIPSFPU";  /* MIPS with FPU */
		case IMAGE_FILE_MACHINE_MIPSFPU16:
			return "IMAGE_FILE_MACHINE_MIPSFPU16"; /* MIPS16 with FPU */
		case IMAGE_FILE_MACHINE_POWERPC:
			return "IMAGE_FILE_MACHINE_POWERPC"; /* Power PC little endian */
		case IMAGE_FILE_MACHINE_R3000:
			return "IMAGE_FILE_MACHINE_R3000";
		case IMAGE_FILE_MACHINE_R4000:
			return "IMAGE_FILE_MACHINE_R4000"; /* MIPS little endian */
		case IMAGE_FILE_MACHINE_R10000:
			return "IMAGE_FILE_MACHINE_R10000";
		case IMAGE_FILE_MACHINE_SH3:
			return "IMAGE_FILE_MACHINE_SH3"; /* Hitachi SH3 */
		case IMAGE_FILE_MACHINE_SH4:
			return "IMAGE_FILE_MACHINE_SH4"; /* Hitachi SH4 */
		case IMAGE_FILE_MACHINE_THUMB:
			return "IMAGE_FILE_MACHINE_THUMB"; /* Thumb */
		case IMAGE_FILE_MACHINE_AMD64:
			return "IMAGE_FILE_MACHINE_AMD64"; /* x64 */
		default:
			return "@Error "+Integer.toHexString(getMachine());
		}
	}

	/**
	 * Return an ArrayList containing the characteristics of this header as Strings
	 * @return the array list with the characteristics
	 */
	public ArrayList<String> printCharacteristics() {
		ArrayList<String> list = new ArrayList<String>();
		short temp = getCharacteristics();
		if ((temp & 0x0001) != 0)
			list.add("IMAGE_FILE_RELOCS_STRIPPED");
		if ((temp & 0x0002) != 0)
			list.add("IMAGE_FILE_EXECUTABLE_IMAGE");
		if ((temp & 0x0004) != 0)
			list.add("IMAGE_FILE_LINE_NUMS_STRIPPED");
		if ((temp & 0x0008) != 0)
			list.add("IMAGE_FILE_LOCAL_SYMS_STRIPPED");
		if ((temp & 0x0010) != 0)
			list.add("IMAGE_FILE_AGGRESSIVE_WS_TRIM");
		if ((temp & 0x0020) != 0)
			list.add("IMAGE_FILE_LARGE_ADDRESS_AWARE");
		if ((temp & 0x0040) != 0)
			list.add("IMAGE_FILE_16BIT_MACHINE");
		if ((temp & 0x0080) != 0)
			list.add("IMAGE_FILE_BYTES_REVERSED_LO");
		if ((temp & 0x0100) != 0)
			list.add("IMAGE_FILE_32BIT_MACHINE");
		if ((temp & 0x0200) != 0)
			list.add("IMAGE_FILE_DEBUG_STRIPPED");
		if ((temp & 0x0400) != 0)
			list.add("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP");
		if ((temp & 0x1000) != 0)
			list.add("IMAGE_FILE_SYSTEM");
		if ((temp & 0x2000) != 0)
			list.add("IMAGE_FILE_DLL");
		if ((temp & 0x4000) != 0)
			list.add("IMAGE_FILE_UP_SYSTEM_ONLY");
		return list;
	}

}
