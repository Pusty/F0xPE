package pusty.f0xpe.pe;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.location.Address;

/** 
 *  Parser for 64bit PE Windows Executables
 *  Only supports executables up to the size of 2GB!
*/
public class ExecutableReader64 extends ExecutableReader {

	/**
	 * Create a new ExecutableReader by supplying an InputStream to read the 64bit PE File from
	 * @param is the InputStream to buffer and parse
	 * @throws Exception something went wrong
	 */
	public ExecutableReader64(InputStream is) throws Exception {
		super(is);
	}
	
	/**
	 * Create a new ExecutableReader by supplying an already buffered ExecutableStream containing a 64bit PE File
	 * @param stream the ExecutableStream with the binary inside
	 * @throws Exception something went wrong
	 */
	public ExecutableReader64(ExecutableStream stream) throws Exception {
		super(stream);
	}
	
	@Override
	public ExecutableStream getStream() {
		return exStr;
	}
	
	@Override
	public void save(File file) throws Exception {
		super.save(file);
	}
	@Override
	public void read(ExecutableStream s) throws Exception {
		dosHeader = new IMAGE_DOS_HEADER(this);
		if(dosHeader.getE_magic()==0x5a4d) { //MZ HEADER FOUND
			s.setIndex(dosHeader.getE_lfanew());
			signature = s.readAddrInt();
		}else if(dosHeader.getE_magic()==0x4550){ //PE HEADER FOUND
			signature = dosHeader.getE_magic();
			getStream().setIndex(getStream().getIndex()+2); //MZ only reads short but int must be read
		}else {
			System.out.println("[!] File isn't an executable."); return;
		}
		if(getSignature()!=0x4550){System.out.println("[!] Signature isn't PE00 format."); return;}
		peHeader = new IMAGE_FILE_HEADER(this); //parse the file header and check if this is a 64bit binary
		if(peHeader.getMachine() != IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE_AMD64) {
			System.out.println("[!] Isn't a 64bit executable");
			return;
		}
		peOptionalHeader = new IMAGE_OPTIONAL_HEADER64(this);  //parse the optional header for 32bit
		peFileSections = new IMAGE_SECTION_HEADER[peHeader.getNumberOfSections()];
		for(int i=0;i<peFileSections.length;i++)
			peFileSections[i]	= new IMAGE_SECTION_HEADER(this); //parse the sections

		
		peOptionalHeader.parseDirectories(); //parse the directories of this PE File
	}
	
	@Override
	public int addr2offset(Address address) {
		return rva2offset(new Address(address.getAddr64()-((IMAGE_OPTIONAL_HEADER64)peOptionalHeader).getImageBase64()));
	}
	
	@Override
	public int rva2offset(Address address) {
		int offset = -1;
		for(IMAGE_SECTION_HEADER section:peFileSections) {
			if(address.getAddr64() >= section.getVirtualAddress()
			&& address.getAddr64() < section.getVirtualAddress() + section.getVirtualSize()) {
				offset = (int) (address.getAddr64() - section.getVirtualAddress() + section.getPointerToRawData());
				return offset;
			}
		}
		if(address.getAddr64() < peOptionalHeader.getSizeOfHeaders())
			return (int) address.getAddr64();
		return offset;
	}
	
	@Override
	public Address offset2rva(int offset) {
		for(IMAGE_SECTION_HEADER section:peFileSections) {
			if(section.getPointerToRawData() != 0 && offset >= section.getPointerToRawData()
			&& offset < section.getPointerToRawData() + section.getSizeOfRawData()) {
				return new Address(offset - section.getPointerToRawData() + section.getVirtualAddress());
			}
		}
		if(offset < peOptionalHeader.getSizeOfHeaders())
			return new Address(offset);
		System.out.println(Integer.toHexString(offset));
		return null;
	}
	
	
	@Override
	public IMAGE_OPTIONAL_HEADER32 getOptionalHeader32() { return null; }
	@Override
	public IMAGE_OPTIONAL_HEADER64 getOptionalHeader64() { return (IMAGE_OPTIONAL_HEADER64) peOptionalHeader; }
	
	@Override
	public boolean is32bit() {
		return false;
	}
	@Override
	public String getArch() {
		return "pex86-64";
	}
	
	@Override
	public Address getDummyAddress(String name) {
		     if(name.equalsIgnoreCase("A")) return new Address(0xAAAAAAAAAAAAAAAAL);
		else if(name.equalsIgnoreCase("B")) return new Address(0xBBBBBBBBBBBBBBBBL);
		else if(name.equalsIgnoreCase("C")) return new Address(0xCCCCCCCCCCCCCCCCL);
		else if(name.equalsIgnoreCase("D")) return new Address(0xDDDDDDDDDDDDDDDDL);
		else if(name.equalsIgnoreCase("E")) return new Address(0xEEEEEEEEEEEEEEEEL);
		else if(name.equalsIgnoreCase("F")) return new Address(0xFFFFFFFFFFFFFFFFL);
		return new Address(0);
	}
	
	/**
	 * Create a 64bit ExecutabeReader by just supplying a File
	 * @param file the file to parse as a 64bit PE File
	 * @return the resulting ExecutableReader after parsing
	 * @throws Exception something went wrong
	 */
	public static ExecutableReader64 createSpecific(File file) throws Exception {
		FileInputStream fis = new FileInputStream(file);		
		ExecutableReader64 reader = new ExecutableReader64(fis);
		fis.close();
		return reader;
	}

}
