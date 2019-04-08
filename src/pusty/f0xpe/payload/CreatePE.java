package pusty.f0xpe.payload;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.pe.ExecutableReader;
import pusty.f0xpe.pe.IMAGE_DOS_HEADER;
import pusty.f0xpe.pe.IMAGE_FILE_HEADER;
import pusty.f0xpe.pe.IMAGE_OPTIONAL_HEADER32;
import pusty.f0xpe.pe.IMAGE_SECTION_HEADER;

/** A Class meant to help in the creation of fully functional PE files. */
public class CreatePE {
	
	public static void createPE() {
		try {
			
		byte[] data = new byte[0x1000*3];
		int[] dosC = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00};
		
		for(int i=0;i<dosC.length;i++)
			data[i] = (byte)dosC[i];
		ByteArrayInputStream bis = new ByteArrayInputStream(data);
		ExecutableReader reader = null;
		reader = new ExecutableReaderDummy(bis);
		IMAGE_DOS_HEADER dosHeader = new IMAGE_DOS_HEADER(reader);
		reader.getStream().setIndex(dosHeader.getE_lfanew());
		reader.getStream().readAddrInt();
		IMAGE_FILE_HEADER peHeader = new IMAGE_FILE_HEADER(reader);
		peHeader.setMachine(IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE_I386);
		peHeader.setNumberOfSections((short)1);
		peHeader.setCharacteristics((short)(0x307)); //PE 32bit
		IMAGE_OPTIONAL_HEADER32 peOptionalHeader = new IMAGE_OPTIONAL_HEADER32(reader);
		peOptionalHeader.setMagic((short)0x10B);
		peOptionalHeader.setImageBase(0x400000);
		peOptionalHeader.setBaseOfCode(0x1000);
		peOptionalHeader.setBaseOfData(0x2000);
		peOptionalHeader.setFileAlignment(0x200);
		peOptionalHeader.setSectionAlignment(0x1000);
		peOptionalHeader.setSubsystem((short)3);
		peOptionalHeader.setMajorLinkerVersion((char)1);
		peOptionalHeader.setMinorLinkerVersion((char)3);
		peOptionalHeader.setMajorOperatingSystemVersion((short)4);
		peOptionalHeader.setMinorOperatingSystemVersion((short)0);
		peOptionalHeader.setMajorImageVersion((short)1);
		peOptionalHeader.setMinorImageVersion((short)0);
		peOptionalHeader.setMajorSubsystemVersion((short)4);
		peOptionalHeader.setMinorSubsystemVersion((short)0);	
		peOptionalHeader.setNumberOfRvaAndSizes(0x10);
		peOptionalHeader.setSizeOfHeapCommit(0x1000);
		peOptionalHeader.setSizeOfHeapReserve(0x100000);
		peOptionalHeader.setSizeOfStackCommit(0x1000);
		peOptionalHeader.setSizeOfStackReserve(0x200000);
		reader.getStream().setIndex(peOptionalHeader.offset());
		peOptionalHeader = new IMAGE_OPTIONAL_HEADER32(reader);
		
		peHeader.setSizeOfOptionalHeader((short)peOptionalHeader.sizeof());
		IMAGE_SECTION_HEADER[] peFileSections = new IMAGE_SECTION_HEADER[peHeader.getNumberOfSections()];
		for(int i=0;i<peFileSections.length;i++) {
			peFileSections[i]	= new IMAGE_SECTION_HEADER(reader);
			peFileSections[i].setName(".text");
			peFileSections[i].setVirtualSize(0x500);
			peFileSections[i].setSizeOfRawData(0x1000);
			peFileSections[i].setVirtualAddress(0x1000*(i+1));
			//peFileSections[i].setCharacteristics(IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_CODE | IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_READ | IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_WRITE | IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_EXECUTE);
			peFileSections[i].setCharacteristics(0x60500060);
			
		}
		peOptionalHeader.setCheckSum(0x118D9);
		peHeader.setTimeDateStamp(0x5958EB56);
		
		
		peOptionalHeader.setSizeOfHeaders(0x400);
		peOptionalHeader.setSizeOfCode(0x500);
		peOptionalHeader.setSizeOfInitializedData(0x500);
		peOptionalHeader.setSizeOfImage(0x3000);
		peOptionalHeader.setAddressOfEntryPoint(0x1000);
		for(int i=0;i<peFileSections.length;i++) {
			peFileSections[i].setPointerToRawData(0x400+i*0x1000);
			reader.getStream().setByte(peFileSections[i].getPointerToRawData(), (byte)0xC3);
		}
		
		
		bis.close();
		data = reader.getStream().getData();
		bis = new ByteArrayInputStream(data);
		reader = new ExecutableReader(bis);
		ModifyPE.injectSection(reader, ".data", 0x500, 0xC0300040);
		bis.close();
		reader.save(new File("create.exe"));
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	public static void main(String[] args)  {
		createPE();
	}
	
	public static class ExecutableReaderDummy extends ExecutableReader {

		public ExecutableReaderDummy(ExecutableStream stream) throws Exception {
			super(stream);
		}
		
		public ExecutableReaderDummy(InputStream is) throws Exception {
			super(is);
		}

		public void read(ExecutableStream s) throws Exception {}
		
	}
}
