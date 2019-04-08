package pusty.f0xpe.location;

import java.util.ArrayList;
import java.util.Collections;

import pusty.f0xpe.pe.ExecutableReader;
import pusty.f0xpe.pe.IMAGE_SECTION_HEADER;

/**
 * Class meant for searching memory for specific patterns and code caves.
 */
public class SectionSearcher {
	protected MemorySection[] sections;

	
	public static final int TYPE_CC = 0x1;
	public static final int TYPE_00 = 0x2;
	public static final int TYPE_90 = 0x4;

	public static final int MODE_SAFE = TYPE_CC; // Only searches for 0xCC as
													// it's not possible for
													// correct code
	public static final int MODE_NORMAL = TYPE_CC | TYPE_00; // Searches for
																// 0xCC and 0x00
	public static final int MODE_RISKY = TYPE_CC | TYPE_00 | TYPE_90; // Searches
																		// for
																		// 0xCC
																		// and
																		// 0x00
																		// and
																		// 0x90

	protected int MIN_SIZE;
	protected int MODE = 0;

	/**
	 * Create a new searcher with a given minimum size and mode to search in.
	 * @param min the minum size for the caves to search for
	 * @param mode the mode used for searching (meaning the allowed opcodes for caves)
	 */
	public SectionSearcher(int min, int mode) {
		MIN_SIZE = min;
		MODE = mode;
	}
	
	
	/**
	 * Create a new searcher with a minimum size of 16 and a given mode to operate with.
	 * @param mode the mode used for searching (meaning the allowed opcodes for caves)
	 */
	public SectionSearcher(int mode) {
		this(16, mode);
	}

	/**
	 * Search for caves for the x86 architecture
	 * @param reader the ExecutableReader containing the binary
	 * @param sections the sections to iterate through
	 * @return an ArrayList containing all the criteria matching MemorySection's
	 */
	private ArrayList<MemorySection> searchIntel(ExecutableReader reader, IMAGE_SECTION_HEADER[] sections) {
		ArrayList<MemorySection> secList = new ArrayList<MemorySection>();
		try {
			int secAmount = sections.length;
			for (int i = 0; i < secAmount; i++) {
				IMAGE_SECTION_HEADER section = sections[i];
				int size = section.getSizeOfRawData();
				int pos = section.getPointerToRawData();
				if (size == 0)
					continue;
				int mem = 0;
				int start = 0;
				boolean foundB = false;
				byte foundByte = 0;
				for (int b = 0; b < size; b++) {
					if (foundB == false) {
						if ((MODE & TYPE_00) != 0) {
							if (reader.getStream().getData()[pos + b] == 0) {
								foundB = true;
								foundByte = 0;
							}
						}
						if ((MODE & TYPE_CC) != 0) {
							if (reader.getStream().getData()[pos + b] == (byte) 0xCC) {
								foundB = true;
								foundByte = (byte) 0xCC;
							}
						}
						if ((MODE & TYPE_90) != 0) {
							if (reader.getStream().getData()[pos + b] == (byte) 0x90) {
								foundB = true;
								foundByte = (byte) 0x90;
							}
						}
					}
					if (foundB == true) {
						if (reader.getStream().getData()[pos + b] == foundByte) {
							if (mem == 0)
								start = pos + b;
							mem++;
						} else {
							if (mem >= MIN_SIZE)
								secList.add(new MemorySection(start, pos + b
										- 1, section));
							mem = 0;
							foundB = false;
							foundByte = 0;
						}
					}
				}
				if (mem >= MIN_SIZE)
					secList.add(new MemorySection(start, pos + size - 1,
							section));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return secList;
	}

	/**
	 * Search the memory of the ExecutableReader for code caves fitting it and return the total resulting size of all caves
	 * @param reader the ExecutableReader containing the binary to search
	 * @return the total size of all matching code caves
	 */
	public int search(ExecutableReader reader) {
		ArrayList<MemorySection> secList = null;
		
		secList = searchIntel(reader, reader.getSectionHeader());
		
		Collections.reverse(secList); // Reverse so it's low address to high
										// address
		sections = secList.toArray(new MemorySection[secList.size()]);
		int m = 0;
		for (int i = 0; i < secList.size(); i++)
			m = m + sections[i].getSize();
		return m;

	}

	/**
	 * Returns the biggest code cave matching the mode
	 * @return a MemorySection object of the biggest match
	 */
	public MemorySection getBiggest() {
		int ts = 0;
		int ms = 0;
		int bi = 0;
		for (int i = 0; i < sections.length; i++) {
			ts = sections[i].getSize();
			if (ts > ms) {
				ms = ts;
				bi = i;
			}
		}
		return sections[bi];
	}

	/**
	 * Return an array containing all matching sections
	 * @return an array which contains all matching sections after a search
	 */
	public MemorySection[] getResults() {
		return sections;
	}

}
