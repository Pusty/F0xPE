package pusty.f0xpe.pe;

import java.io.IOException;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.pe.ExecutableReader;

/**
 * A class representing the IMAGE_OPTIONAL_HEADER64 structure in a given binary reader.
 * <br>Reference: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header
 * <br>Header: winnt.h
 */
public class IMAGE_OPTIONAL_HEADER64 extends IMAGE_OPTIONAL_HEADER32 {

	//See PEOptionHeader for documentation, almost the same
	
	/** 
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#ImageBase}
	 * @see IMAGE_OPTIONAL_HEADER32#ImageBase
	 */
	protected int ImageBase64;
	
	/** 
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#SizeOfStackReserve}
	 * @see IMAGE_OPTIONAL_HEADER32#SizeOfStackReserve
	 */
	protected int SizeOfStackReserve64;
	
	/** 
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#SizeOfStackCommit}
	 * @see IMAGE_OPTIONAL_HEADER32#SizeOfStackCommit
	 */
	protected int SizeOfStackCommit64;
	
	/** 
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#SizeOfHeapReserve}
	 * @see IMAGE_OPTIONAL_HEADER32#SizeOfHeapReserve
	 */
	protected int SizeOfHeapReserve64;
	
	/** 
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#SizeOfHeapCommit}
	 * @see IMAGE_OPTIONAL_HEADER32#SizeOfHeapCommit
	 */
	protected int SizeOfHeapCommit64;
	

    /**
     * Parse a IMAGE_OPTIONAL_HEADER64 at the current reader position
     * @param reader the reader containing the binary data to parse
     * @throws Exception something went wrong
     */
	public IMAGE_OPTIONAL_HEADER64(ExecutableReader reader)
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
		ImageBase64 = s.readAddrLong();
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
		SizeOfStackReserve64 = s.readAddrLong();
		SizeOfStackCommit64 = s.readAddrLong();
		SizeOfHeapReserve64 = s.readAddrLong();
		SizeOfHeapCommit64 = s.readAddrLong();
		LoaderFlags = s.readAddrInt();
		NumberOfRvaAndSizes = s.readAddrInt();
		for (int i = 0; i < DataDirectory.length; i++)
			DataDirectory[i] = new IMAGE_DATA_DIRECTORY(reader);
		

	}
	@Override
	public boolean is32bit() { return false; }
	
	/** 
	 * The preferred address of the first byte of the image when loaded in memory
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#getImageBase()}
	 * @return the preferred address to load the image at
	 */
	public long getImageBase64() {
		try {
			return reader.getStream().getLong(ImageBase64);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/** 
	 * Set the preferred address of the first byte of the image when loaded in memory
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#setImageBase(int)}
	 * @param imageBase64 the new preferred address to load the image at
	 */
	public void setImageBase64(long imageBase64) {
		try {
			reader.getStream().setLong(ImageBase64, imageBase64);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/** 
	 * Return the amount of bytes reserved for the stack of this image file
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#getSizeOfStackReserve()}
	 * @return the amount of bytes reserved for the stack
	 */
	public long getSizeOfStackReserve64() {
		try {
			return reader.getStream().getLong(SizeOfStackReserve64);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/** 
	 * Set the amount of bytes reserved for the stack of this image file
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#setSizeOfStackReserve(int)}
	 * @param sizeOfStackReserve64 the new amount of bytes reserved for the stack
	 */
	public void setSizeOfStackReserve64(long sizeOfStackReserve64) {
		try {
			reader.getStream().setLong(SizeOfStackReserve64, sizeOfStackReserve64);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/** 
	 * Return the amount of bytes committed to the stack at load time
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#getSizeOfStackCommit()}
	 * @return the amount of bytes initially committed to the stack
	 */
	public long getSizeOfStackCommit64() {
		try {
			return reader.getStream().getLong(SizeOfStackCommit64);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/** 
	 * Set the amount of bytes committed to the stack at load time
	 * 64bit version of {@link IMAGE_OPTIONAL_HEADER32#setSizeOfStackCommit(int)}
	 * @param sizeOfStackCommit64  the new amount of bytes initially committed to the stack
	 */
	public void setSizeOfStackCommit64(long sizeOfStackCommit64) {
		try {
			reader.getStream().setLong(SizeOfStackCommit64, sizeOfStackCommit64);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/** 
	 * Return the amount of bytes reserved for the heap of this image file
	 * <br> 64bit version of {@link IMAGE_OPTIONAL_HEADER32#getSizeOfHeapReserve()}
	 * @return the amount of bytes reserved for the heap
	 */
	public long getSizeOfHeapReserve64() {
		try {
			return reader.getStream().getLong(SizeOfHeapReserve64);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/** 
	 * Set the amount of bytes reserved for the heap of this image file
	 * <br> 64bit version of {@link IMAGE_OPTIONAL_HEADER32#setSizeOfHeapReserve(int)}
	 * @param sizeOfHeapReserve64 the new amount of bytes reserved for the heap
	 */
	public void setSizeOfHeapReserve64(long sizeOfHeapReserve64) {
		try {
			reader.getStream().setLong(SizeOfHeapReserve64, sizeOfHeapReserve64);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/** 
	 * Return the amount of bytes committed to the heap at load time
	 * <br> 64bit version of {@link IMAGE_OPTIONAL_HEADER32#getSizeOfHeapCommit()}
	 * @return the amount of bytes initially committed to the heap
	 */
	public long getSizeOfHeapCommit64() {
		try {
			return reader.getStream().getLong(SizeOfHeapCommit64);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/** 
	 * Set the amount of bytes committed to the heap at load time
	 * <br> 64bit version of {@link IMAGE_OPTIONAL_HEADER32#setSizeOfHeapCommit(int)}
	 * @param sizeOfHeapCommit64 the new amount of bytes initially committed to the heap
	 */
	public void setSizeOfHeapCommit64(long sizeOfHeapCommit64) {
		try {
			reader.getStream().setLong(SizeOfHeapCommit64, sizeOfHeapCommit64);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	
}
