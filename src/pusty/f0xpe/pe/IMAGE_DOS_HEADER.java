package pusty.f0xpe.pe;

import java.io.IOException;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.pe.ExecutableReader;

/**
 * A class representing the IMAGE_DOS_HEADER structure in a given binary reader.
 * <br>Header: winnt.h
 */
public class IMAGE_DOS_HEADER extends ReadableObject {

	/** Magic number */
	protected int e_magic;
	/** Bytes on last page of file */
	protected int e_cblp; 
	/** Pages in file */
	protected int e_cp;
	/** Relocations */
	protected int e_crlc;
	/** Size of header in paragraphs */
	protected int e_cparhdr;
	/** Minimum extra paragraphs needed */
	protected int e_minalloc;
	/**  Maximum extra paragraphs needed */
	protected int e_maxalloc;
	/** Initial (relative) SS value */
	protected int e_ss;
	/** Initial SP value */
	protected int e_sp;
	/** Checksum */
	protected int e_csum;
	/**  Initial IP value */
	protected int e_ip;
	/** Initial (relative) CS value */
	protected int e_cs;
	/** File offset of relocation table */
	protected int e_lfarlc;
	/** Overlay number */
	protected int e_ovno;
	/** Reserved words */
	protected int[] e_res = new int[4];
	/** OEM identifier (for e_oeminfo) */
	protected int e_oemid;
	/**  OEM information; e_oemid specific */
	protected int e_oeminfo;
	/** Reserved words */
	protected int[] e_res2 = new int[10];
	/** File offset of new NT header */
	protected int e_lfanew;

    /**
     * Parse a IMAGE_DOS_HEADER at the current reader position
     * @param reader the reader containing the binary data to parse
     * @throws Exception something went wrong
     */
	public IMAGE_DOS_HEADER(ExecutableReader reader)
			throws Exception {
		super(reader);
	}

	@Override
	public void read(ExecutableStream s) throws Exception {
		e_magic = s.readAddrShort(); // Magic number
		if(s.getShort(e_magic) != 0x5a4d) return; //MZ Header
		e_cblp = s.readAddrShort(); // Bytes on last page of file
		e_cp = s.readAddrShort(); // Pages in file
		e_crlc = s.readAddrShort(); // Relocations
		e_cparhdr = s.readAddrShort(); // Size of header in paragraphs
		e_minalloc = s.readAddrShort(); // Minimum extra paragraphs needed
		e_maxalloc = s.readAddrShort(); // Maximum extra paragraphs needed
		e_ss = s.readAddrShort(); // Initial (relative) SS value
		e_sp = s.readAddrShort(); // Initial SP value
		e_csum = s.readAddrShort(); // Checksum
		e_ip = s.readAddrShort(); // Initial IP value
		e_cs = s.readAddrShort(); // Initial (relative) CS value
		e_lfarlc = s.readAddrShort(); // File address of relocation table
		e_ovno = s.readAddrShort(); // Overlay number
		e_res = new int[4]; // Reserved words
		for (int i = 0; i < e_res.length; i++)
			e_res[i] = s.readAddrShort();
		e_oemid = s.readAddrShort(); // OEM identifier (for e_oeminfo)
		e_oeminfo = s.readAddrShort(); // OEM information; e_oemid specific
		e_res2 = new int[10]; // Reserved words
		for (int i = 0; i < e_res2.length; i++)
			e_res2[i] = s.readAddrShort();
		e_lfanew = s.readAddrInt(); // File address of new exe header
	}
	

	/**
	 * Return the offset within the file to the e_lfanew field
	 * @return the offset to the e_lfanew field
	 */
	protected int getE_lfanewAddr() {
		return e_lfanew;
	}

	/**
	 * Return the "MZ" magic value of this executable
	 * @return return the first two bytes representing the magic value
	 */
	public short getE_magic() {
		try {
			return reader.getStream().getShort(e_magic);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the magic value of this executable. It will be invalid it not set to 0x5a4d ("MZ")
	 * @param e_magic the new magic value of this reader
	 */
	public void setE_magic(short e_magic) {
		try {
			reader.getStream().setShort(this.e_magic, e_magic);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the bytes on the last page of the file (DOS ONLY)
	 * @return the bytes on the last page of a file
	 */
	public short getE_cblp() {
		try {
			return reader.getStream().getShort(e_cblp);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the bytes on the last page of the file (DOS ONLY)
	 * @param e_cblp the new bytes on the last page of a file
	 */
	public void setE_cblp(short e_cblp) {
		try {
			reader.getStream().setShort(this.e_cblp, e_cblp);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the amount of pages in the file (DOS ONLY)
	 * @return the amount of pages in the file
	 */
	public short getE_cp() {
		try {
			return reader.getStream().getShort(e_cp);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the amount of pages in the file (DOS ONLY)
	 * @param e_cp the new amount of pages in the file
	 */
	public void setE_cp(short e_cp) {
		try {
			reader.getStream().setShort(this.e_cp, e_cp);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the relocations (DOS ONLY)
	 * @return the relocations
	 */
	public short getE_crlc() {
		try {
			return reader.getStream().getShort(e_crlc);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the relocations (DOS ONLY)
	 * @param e_crlc the new relocations
	 */
	public void setE_crlc(short e_crlc) {
		try {
			reader.getStream().setShort(this.e_crlc, e_crlc);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Set the size of header the in paragraphs (DOS ONLY)
	 * @return the size of the header in paragraphs
	 */
	public short getE_cparhdr() {
		try {
			return reader.getStream().getShort(e_cparhdr);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the size of the header in paragraphs (DOS ONLY)
	 * @param e_cparhdr the new size of the header in paragraphs
	 */
	public void setE_cparhdr(short e_cparhdr) {
		try {
			reader.getStream().setShort(this.e_cparhdr, e_cparhdr);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the minimum amount extra paragraphs needed (DOS ONLY)
	 * @return the minimum amount extra paragraphs needed
	 */
	public short getE_minalloc() {
		try {
			return reader.getStream().getShort(e_minalloc);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the minimum amount extra paragraphs needed (DOS ONLY)
	 * @param e_minalloc the new minimum amount extra paragraphs needed
	 */
	public void setE_minalloc(short e_minalloc) {
		try {
			reader.getStream().setShort(this.e_minalloc, e_minalloc);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the maximum amount extra paragraphs needed (DOS ONLY)
	 * @return the maximum amount extra paragraphs needed
	 */
	public short getE_maxalloc() {
		try {
			return reader.getStream().getShort(e_maxalloc);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the maximum amount extra paragraphs needed (DOS ONLY)
	 * @param e_maxalloc the new maximum amount extra paragraphs needed
	 */
	public void setE_maxalloc(short e_maxalloc) {
		try {
			reader.getStream().setShort(this.e_maxalloc, e_maxalloc);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Get the initial (relative) SS segment value (DOS ONLY)
	 * @return the initial (relative) SS segment value
	 */
	public short getE_ss() {
		try {
			return reader.getStream().getShort(e_ss);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the initial (relative) SS segment value (DOS ONLY)
	 * @param e_ss the new initial (relative) SS segment value
	 */
	public void setE_ss(short e_ss) {
		try {
			reader.getStream().setShort(this.e_ss, e_ss);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the initial SP register value (DOS ONLY)
	 * @return the initial SP register value
	 */
	public short getE_sp() {
		try {
			return reader.getStream().getShort(e_sp);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the initial SP register value (DOS ONLY)
	 * @param e_sp the new initial SP register value
	 */
	public void setE_sp(short e_sp) {
		try {
			reader.getStream().setShort(this.e_sp, e_sp);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the checksum
	 * @return the checksum
	 */
	public short getE_csum() {
		try {
			return reader.getStream().getShort(e_csum);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the checksum
	 * @param e_csum the new checksum
	 */
	public void setE_csum(short e_csum) {
		try {
			reader.getStream().setShort(this.e_csum, e_csum);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the initial IP register value (DOS ONLY)
	 * @return the initial IP register value
	 */
	public short getE_ip() {
		try {
			return reader.getStream().getShort(e_ip);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the initial IP register value (DOS ONLY)
	 * @param e_ip the new initial IP register value
	 */
	public void setE_ip(short e_ip) {
		try {
			reader.getStream().setShort(this.e_ip, e_ip);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Get the initial (relative) CS segment value (DOS ONLY)
	 * @return the initial (relative) CS segment value
	 */
	public short getE_cs() {
		try {
			return reader.getStream().getShort(e_cs);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the initial (relative) CS segment value (DOS ONLY)
	 * @param e_cs the new initial (relative) CS segment value
	 */
	public void setE_cs(short e_cs) {
		try {
			reader.getStream().setShort(this.e_cs, e_cs);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the file offset of the relocation table (DOS ONLY)
	 * @return the file offset of the relocation table
	 */
	public short getE_lfarlc() {
		try {
			return reader.getStream().getShort(e_lfarlc);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the file offset of the relocation table (DOS ONLY)
	 * @param e_lfarlc the new file offset of the relocation table
	 */
	public void setE_lfarlc(short e_lfarlc) {
		try {
			reader.getStream().setShort(this.e_lfarlc, e_lfarlc);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the overlay number (DOS ONLY)
	 * @return the overlay number
	 */
	public short getE_ovno() {
		try {
			return reader.getStream().getShort(e_ovno);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the overlay number (DOS ONLY)
	 * @param e_ovno the new overlay number
	 */
	public void setE_ovno(short e_ovno) {
		try {
			reader.getStream().setShort(this.e_ovno, e_ovno);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the content of the reserved values
	 * @return the value of the reserved values
	 */
	public short[] getE_res() {
		try {
			short[] output = new short[this.e_res.length];
			for(int i=0;i<this.e_res.length;i++)
				output[i] = reader.getStream().getShort(this.e_res[i]);
			return output;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Set the content of the reserved values
	 * @param e_res the new content of the reserved values
	 */
	public void setE_res(short[] e_res) {
		try {
			for(int i=0;i<this.e_res.length;i++)
				reader.getStream().setShort(this.e_res[i], e_res[i]);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the OEM identifier (DOS ONLY)
	 * @return the OEM identifier
	 */
	public short getE_oemid() {
		try {
			return reader.getStream().getShort(e_oemid);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the OEM identifier (DOS ONLY)
	 * @param e_oemid the new OEM identifier
	 */
	public void setE_oemid(short e_oemid) {
		try {
			reader.getStream().setShort(this.e_oemid, e_oemid);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the OEM information (DOS ONLY)
	 * @return the OEM information
	 */
	public short getE_oeminfo() {
		try {
			return reader.getStream().getShort(e_oeminfo);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * Set the OEM information (DOS ONLY)
	 * @param e_oeminfo the new OEM information
	 */
	public void setE_oeminfo(short e_oeminfo) {
		try {
			reader.getStream().setShort(this.e_oeminfo, e_oeminfo);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Return the content of the second reserved values
	 * @return the value of the second reserved values
	 */
	public short[] getE_res2() {
		try {
			short[] output = new short[this.e_res2.length];
			for(int i=0;i<this.e_res2.length;i++)
				output[i] = reader.getStream().getShort(this.e_res2[i]);
			return output;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Set the content of the second reserved values
	 * @param e_res2 the new content of the second reserved values
	 */
	public void setE_res2(short[] e_res2) {
		try {
			for(int i=0;i<this.e_res2.length;i++)
				reader.getStream().setShort(this.e_res2[i], e_res2[i]);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Return the offset to the PE Header of this executable
	 * @return the offset to the PE Header
	 */
	public int getE_lfanew() {
		try {
			return reader.getStream().getInt(e_lfanew);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}
	
	/**
	 * Set the offset to the PE Header of this executable
	 * @param e_lfanew the new offset to the header
	 */
	public void setE_lfanew(int e_lfanew) {
		try {
			reader.getStream().setInt(this.e_lfanew, e_lfanew);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

}
