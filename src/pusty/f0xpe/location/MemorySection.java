package pusty.f0xpe.location;

import java.util.HashMap;

import pusty.f0xpe.pe.ExecutableReader;
import pusty.f0xpe.pe.IMAGE_SECTION_HEADER;

/**
 * Class for abstracting sections from raw data to a high level format.
 */
public class MemorySection {

	protected int offset_from; //from (index in data array)
	protected int offset_to; //to (index in data array)
	protected IMAGE_SECTION_HEADER section; //section this is in
	protected HashMap<String, Object> data; //data hash for stuff
	
	/**
	 * Create a MemorySection with a given memory range and an associated header
	 * @param from starting point of this section within the actual executable stream
	 * @param to end point of this section within the actual executable stream
	 * @param sec the section header associated to this object
	 */
	public MemorySection(int from, int to, IMAGE_SECTION_HEADER sec) {
		offset_from = from;
		offset_to = to;
		section = sec;
		data = new HashMap<String, Object>();
	}
	
	/**
	 * Create a MemorySection by just supplying a section header
	 * @param sec the section header containing the boundaries for this instance
	 */
	public MemorySection(IMAGE_SECTION_HEADER sec) {
		offset_from = sec.getPointerToRawData();
		offset_to = sec.getPointerToRawData()+sec.getSizeOfRawData();
		section = sec;
		data = new HashMap<String, Object>();
	}
	
	/**
	 * Section header associated to this instance
	 * @return the section header of this memory section
	 */
	public IMAGE_SECTION_HEADER getSection() { return section; }
	/*public Address getAddress() { //this might confuse people, me as well
		return InjectingEngine.fromSection(null, this);  //This has no image base 
	}*/
	
	/**
	 * The start offset of this memory section within the buffer
	 * @return start offset within the executable stream
	 */
	public int getOffsetFrom() { return offset_from; }
	
	/**
	 * The end offset of this memory section within the buffer
	 * @return end offset within the executable stream
	 */
	public int getOffsetTo() { return offset_to; }
	
	/**
	 * The size of this memory section's data
	 * @return size of this memory section
	 */
	public int getSize() { return offset_to-offset_from; }
	
	/**
	 * Return the virtual address this section starts at
	 * @return virtual starting address
	 */
	public int getAddressFrom() {
		return offset_from-section.getPointerToRawData()+section.getVirtualAddress();
	}
	
	/**
	 * Return the virtual address this section ends at
	 * @return virtual ending address
	 */
	public int getAddressTo() {
		return offset_to-section.getPointerToRawData()+section.getVirtualAddress();
	}
	
	/**
	 * Returns a Address object for the beginning of this section
	 * @param reader the reader this memory section is in
	 * @return an instance of an address object representing the rva of the start point
	 */
	public Address getAddress(ExecutableReader reader) {
		return reader.offset2rva(getOffsetFrom());
	}
	
	@Override
	public String toString() {
		return section.getName()+": "+getSize();
	}

	/**
	 *  returnMode = true/false where true = return on end and false = jump on end <br>
	 *  is64bit = true/false <br>
	 *  returnAddr = Address this function should return to <br>
	 */
	public void putData(String string, Object d) {
		data.put(string, d);
	}
	
	/**
	 * Return stored data within this section by its key
	 * @param string the key of the data to return
	 * @return the associated data for this key (or null)
	 */
	public Object getData(String string) {
		if(!data.containsKey(string)) 
			return null; 
		return data.get(string);
	}

	/**
	 * Resize this section by moving the ending offset
	 * @param size the new size of this memory section
	 */
	public void setSize(int size) {
		offset_to = offset_from + size;
	}
	
}
