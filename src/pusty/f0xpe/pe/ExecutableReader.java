package pusty.f0xpe.pe;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.location.Address;

/** 
 *  Parser for 32bit PE Windows Executables
 *  Only supports executables up to the size of 2GB!
*/
public class ExecutableReader  {
	

	/** Neither a 32bit nor a 64bit PE Executable */
	public static final int TYPEID_UNDEFINED = -1;
	/** Partly matches the PE signature but is neither 32bit x86 nor 64bit x86 */
	public static final int TYPEID_PE_GENERIC = 1;
	/** A 32bit x86 PE Executable */
	public static final int TYPEID_PE_x86 = 2;
	/** A 64bit x64 PE Executable */
	public static final int TYPEID_PE_x64 = 3;
	
	protected IMAGE_DOS_HEADER dosHeader; //dos header
	protected int signature; //offset to the signature of this reader preferably PE\x00\x00
	protected IMAGE_FILE_HEADER peHeader; //the PE Header itself
	protected IMAGE_OPTIONAL_HEADER32 peOptionalHeader; //the optional header, for 32bit the 32bit version
	protected IMAGE_SECTION_HEADER[] peFileSections; //the section headers
	
	protected ExecutableStream exStr; //the stream of this reader
	
	/**
	 * Create a new ExecutableReader by supplying an InputStream to read the 32bit PE File from
	 * @param is the InputStream to buffer and parse
	 * @throws Exception something went wrong
	 */
	public ExecutableReader(InputStream is) throws Exception {
		exStr = new ExecutableStream(is);
		read(exStr);
	}
	
	/**
	 * Create a new ExecutableReader by supplying an already buffered ExecutableStream containing a 32bit PE File
	 * @param stream the ExecutableStream with the binary inside
	 * @throws Exception something went wrong
	 */
	public ExecutableReader(ExecutableStream stream) throws Exception {
		exStr = stream;
		read(stream);
	}
	
	/**
	 * Dummy initializer, should not be used
	 */
	private ExecutableReader() {}
	
	/**
	 * Return the Buffered Stream of this ExecutableReader
	 * @return the ExecutableStream containing the binary
	 */
	public ExecutableStream getStream() {
		return exStr;
	}
	
	/**
	 * Save the current content of the ExecutableStream into a file
	 * @param file the file to save the content into
	 * @throws Exception something went wrong when trying to write to the file
	 */
	public void save(File file) throws Exception {
		FileOutputStream fos = new FileOutputStream(file);		
		fos.write(getStream().getData());
		fos.close();
	}
	
	/**
	 * Try to parse the given ExecutableStream into this ExecutableReader. Called on creating an element of this class.
	 * @param s the stream to parse into the variables of this instance
	 * @throws Exception something went wrong
	 */
	public void read(ExecutableStream s) throws Exception {
		dosHeader = new IMAGE_DOS_HEADER(this);
		if(dosHeader.getE_magic()==0x5a4d) { //MZ HEADER FOUND
			s.setIndex(dosHeader.getE_lfanew());
			signature = s.readAddrInt();
		}else if(dosHeader.getE_magic()==0x4550){ //PE HEADER FOUND
			signature = dosHeader.getE_magic();
			getStream().setIndex(getStream().getIndex()+2); //MZ only reads short but int must be read
		}else {
			System.err.println("[!] File isn't an executable."); return;
		}
		if(getSignature()!=0x4550){System.out.println("[!] Signature isn't PE00 format."); return;}
		peHeader = new IMAGE_FILE_HEADER(this); //parse the file header and check if this is a 32bit binary
		if(peHeader.getMachine() != IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE_I386) {
			System.err.println("[!] Isn't a 32bit executable");
			return;
		}
		peOptionalHeader = new IMAGE_OPTIONAL_HEADER32(this); //parse the optional header for 32bit
		peFileSections = new IMAGE_SECTION_HEADER[peHeader.getNumberOfSections()];
		for(int i=0;i<peFileSections.length;i++)
			peFileSections[i]	= new IMAGE_SECTION_HEADER(this); //parse the sections
		
		peOptionalHeader.parseDirectories(); //parse the directories of this PE File
	}
	
	
	/**
	 * Convert an absolute Address object to a offset within the binary relative to the Image Base
	 * @param address the absolute address object to convert
	 * @return the offset within the binary
	 */
	public int addr2offset(Address address) {
		return rva2offset(new Address(address.getAddr32()-peOptionalHeader.getImageBase()));
	}
	
	
	/**
	 * Convert a relative virtual address to an offset within the binary.
	 * @param address the RVA to convert
	 * @return the offset within the binary
	 */
	public int rva2offset(Address address) {
		int offset = -1;
		for(IMAGE_SECTION_HEADER section:peFileSections) {
			if(address.getAddr32() >= section.getVirtualAddress()
			&& address.getAddr32() < section.getVirtualAddress() + section.getVirtualSize()) {
				offset = address.getAddr32() - section.getVirtualAddress() + section.getPointerToRawData();
				return offset;
			}
		}
		if(address.getAddr32() < peOptionalHeader.getSizeOfHeaders())
			return address.getAddr32();
		return offset;
	}
	
	/**
	 * Convert a offset within the binary to a relative virtual address.
	 * @param offset the offset within the binary
	 * @return the calculated RVA
	 */
	public Address offset2rva(int offset) {
		for(IMAGE_SECTION_HEADER section:peFileSections) {
			if(section.getPointerToRawData() != 0 && offset >= section.getPointerToRawData()
			&& offset < section.getPointerToRawData() + section.getSizeOfRawData()) {
				return new Address(offset - section.getPointerToRawData() + section.getVirtualAddress());
			}
		}
		if(offset < peOptionalHeader.getSizeOfHeaders())
			return new Address(offset);
		return null;
	}
	
	/**
	 * Return the IMAGE_DOS_HEADER of the PE File represented by this ExecutableReader.
	 * @return the DOS/MZ Header of this reader
	 */
	public IMAGE_DOS_HEADER getDOSHeader() { return dosHeader; }
	
	/**
	 * Return the IMAGE_FILE_HEADER of the PE File represented by this ExecutableReader.
	 * @return the File Header of this reader
	 */
	public IMAGE_FILE_HEADER getFileHeader() { return peHeader; }
	
	/**
	 * Return the generic IMAGE_OPTIONAL_HEADER of the PE File represented by this ExecutableReader.
	 * @return the Optional Header of this reader
	 */
	public IMAGE_OPTIONAL_HEADER32 getOptionalHeader() { return peOptionalHeader; }
	
	/**
	 * Return the IMAGE_OPTIONAL_HEADER32 this ExecutableReader if it's 32bit.
	 * @return the Optional Header of this reader
	 */
	public IMAGE_OPTIONAL_HEADER32 getOptionalHeader32() { return (IMAGE_OPTIONAL_HEADER32) peOptionalHeader; }
	
	/**
	 * Return the IMAGE_OPTIONAL_HEADER64 this ExecutableReader if it's 64bit.
	 * @return the Optional Header of this reader
	 */
	public IMAGE_OPTIONAL_HEADER64 getOptionalHeader64() { return null; }
	
	/**
	 * Return the IMAGE_SECTION_HEADER array of the PE File represented by this ExecutableReader.
	 * @return the array containing all Section Headers of this reader
	 */
	public IMAGE_SECTION_HEADER[]  getSectionHeader() { return peFileSections; }
	
	/**
	 * Return a specific section by name, padded with 0 bytes to match the format. Will return null if not found.
	 * @param str the section to search for
	 * @return the first Section Header that has this name. null if not found
	 */
	public IMAGE_SECTION_HEADER getSection(String str) {
		for(int i=str.length();i<IMAGE_SECTION_HEADER.IMAGE_SIZEOF_SHORT_NAME;i++)
			str += (char)0;
		for(IMAGE_SECTION_HEADER ish:peFileSections) {
			if(ish.getName().equals(str))
				return ish;
		}
		return null;
	}
	
	/**
	 * Return the Signature of this reader
	 * @return the signature of this reader
	 */
	public int getSignature() {
		try {
			return getStream().getInt(signature);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the Signature of this reader
	 * @param signature the new signature of this reader
	 */
	public void setSignature(short signature) {
		try {
			getStream().setInt(this.signature, signature);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return whether this reader represents a x86 32bit binary.
	 * @return if the binary parsed in this reader is a 32bit one.
	 */
	public boolean is32bit() {
		return true;
	}
	
	/**
	 * Output an CPU architecture string
	 * @return a string containing the name of the architecture
	 */
	public String getArch() {
		return "pex86";
	}
	
	/**
	 * Returns a dummy address fitting the architecture of the reader
	 * <br> Currently Supported Dummy Addresses:
	 * <br> "A", "B", "C", "D", "E", "F"
	 * 
	 * @return a fitting dummy address meant for dynamic replacement of values
	 */
	public Address getDummyAddress(String name) {
		     if(name.equalsIgnoreCase("A")) return new Address(0xAAAAAAAA);
		else if(name.equalsIgnoreCase("B")) return new Address(0xBBBBBBBB);
		else if(name.equalsIgnoreCase("C")) return new Address(0xCCCCCCCC);
		else if(name.equalsIgnoreCase("D")) return new Address(0xDDDDDDDD);
		else if(name.equalsIgnoreCase("E")) return new Address(0xEEEEEEEE);
		else if(name.equalsIgnoreCase("F")) return new Address(0xFFFFFFFF);
		return new Address(0);
	}
	
	/**
	 * Create a 32bit ExecutabeReader by just supplying a File
	 * @param file the file to parse as a 32bit PE File
	 * @return the resulting ExecutableReader after parsing
	 * @throws Exception something went wrong
	 */
	public static ExecutableReader createSpecific(File file) throws Exception {
		
		FileInputStream fis = new FileInputStream(file);		
		ExecutableReader reader = new ExecutableReader(fis);
		fis.close();
		return reader;
	}	

	
	/**
	 * Refresh the content of a 32bit Executable Reader with the content of a file
	 * @param reader the reader to refresh
	 * @param file the file to use for refreshing
	 * @throws Exception something went wrong
	 */
	public static void rewrite(ExecutableReader reader, File file) throws Exception {
		FileInputStream fis = new FileInputStream(file);		
		reader.exStr = new ExecutableStream(fis);
		reader.read(reader.exStr);
		fis.close();
	}
	
	/**
	 * Refresh the content of a 32bit ExecutableReader with the content of a byte array
	 * @param reader the reader to refresh
	 * @param data the byte array to use for refreshing
	 * @throws Exception
	 */
	public static void rewrite(ExecutableReader reader, byte[] data) throws Exception {
		reader.exStr = new ExecutableStream(data);
		reader.read(reader.exStr);
	}
	
	/**
	 * Reload a generic ExecutableReader
	 * @param in the 32bit or 64bit ExecutableReader to reload
	 * @return the reloaded executable reader
	 * @throws Exception something went wrong
	 */
	public static ExecutableReader reload(ExecutableReader in) throws Exception {
		ByteArrayInputStream bis = new ByteArrayInputStream(in.getStream().getData());
		ExecutableReader reader = null;
		if(in.is32bit())
			reader = new ExecutableReader(bis);
		else
			reader = new ExecutableReader64(bis);
		bis.close();
		return reader;
	}
	
	
	/**
	 * Identify if this file is matching the basic signature of a 32bit or 64bit PE File
	 * @param file the file to check
	 * @return an integer value containing the result, see TYPEID_* constants for further information
	 * @throws Exception something went wrong
	 */
	public static int identify(File file) throws Exception {
		FileInputStream fis = new FileInputStream(file);
		int result = identify(new ExecutableStream(fis));
		fis.close();
		return result;
	}
	
	/**
	 * Identify if this file is matching the basic signature of a 32bit or 64bit PE File
	 * @param str the ExecutableStream to check
	 * @return an integer value containing the result, see TYPEID_* constants for further information
	 * @throws Exception something went wrong
	 */
	public static int identify(ExecutableStream str) throws Exception {
		ExecutableReader dummy = new ExecutableReader();
		dummy.exStr = str;
		char fstChar = (char)str.getByte(str.readAddrByte());
		char sndChar = (char)str.getByte(str.readAddrByte()); //MZ / PE => PE | ?ELF => ELF
		int result = TYPEID_UNDEFINED;
		if(sndChar == 'Z' || (fstChar == 'P' && sndChar == 'E')) {
			result = TYPEID_PE_GENERIC;
			str.setIndex(0);
			if(sndChar == 'Z') {
				IMAGE_DOS_HEADER dosHeader = new IMAGE_DOS_HEADER(dummy);
				str.setIndex(str.getShort(dosHeader.getE_lfanewAddr()));
			}
			str.readAddrInt(); //PE signature
			short machine = str.getShort(str.readAddrShort());
			if(machine == IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE_I386)
				result = TYPEID_PE_x86;
			else if(machine == IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE_AMD64)
				result = TYPEID_PE_x64;
		}
		str.setIndex(0);
		return result;
	}
	
	/**
	 * Create a generic ExecutableReader based on a file
	 * @param file the file to turn into an ExecutableReader
	 * @return either a 32bit ExecutableReader or a 64bit ExecutableReader or null
	 * @throws Exception something went wrong
	 */
	public static ExecutableReader create(File file) throws Exception {
		FileInputStream fis = new FileInputStream(file);
		ExecutableReader reader = create(new ExecutableStream(fis));
		fis.close();
		return reader;
	}
	
	/**
	 * Create a generic ExecutableReader based on an ExecutableStream
	 * @param str the ExecutableStream to turn into an ExecutableReader
	 * @return either a 32bit ExecutableReader or a 64bit ExecutableReader or null
	 * @throws Exception something went wrong
	 */
	public static ExecutableReader create(ExecutableStream str) throws Exception {
		int identify = identify(str);
		ExecutableReader reader = null;
		switch(identify) {
			case TYPEID_PE_x86:
				reader = new ExecutableReader(str);
			break;
			case TYPEID_PE_x64:
				reader = new ExecutableReader64(str);
			break;
			default:
				System.out.println("[!] Arch not supported (Error: "+identify+")");
		}
		return reader;
	}

	

}
