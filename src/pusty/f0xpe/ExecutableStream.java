package pusty.f0xpe;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 *  This is a class for reading binary data properly from an input stream by buffering it and referencing in it with a pointer.
 */
public class ExecutableStream {

	/** The immutable data of this stream */
	private final byte[] inputData;
	/** The current index within the data */
	private int inputIndex;
	
	/**
	 * Create a new stream for reading and writing binary data in different formats based on a stream
	 * @param is the stream to fully buffer and work with
	 */
	public ExecutableStream(InputStream is) {
		int available = 0;
		try {
			available = is.available();
		} catch (IOException e) {
			e.printStackTrace();
		}
		inputData = new byte[available];
		try {
			is.read(inputData); //this is fast, wow
		}catch(IOException e) {
			e.printStackTrace();
		}
		inputIndex = 0;
	}

	/**
	 * Create a new stream for reading and writing binary data in different formats based on an array
	 * @param data the array this stream reads from and writes to
	 */
	public ExecutableStream(byte[] data) {
		inputData = data;
		inputIndex = 0;
	}
	
	/**
	 * Returns the buffered data
	 * @return the data buffered from the input stream
	 */
	public byte[] getData() {
		return inputData;
	}
	
	/**
	 * Returns the size of the buffered data
	 * @return the length of the buffer from the input stream
	 */
	public int getSize() {
		return inputData.length;
	}
	
	/**
	 * Reset the pointer within the buffer to the beginning
	 */
	public void reset() {
		inputIndex = 0;
	}
	
	/**
	 * Return the pointer within the buffer and move 2 bytes up
	 * @return the offset within the buffer of the read short
	 * @throws IOException tried to move out of bounds
	 */
	public int readAddrShort() throws IOException {
		int temp = inputIndex;
		inputIndex=inputIndex+2;
		if(inputIndex > inputData.length) throw new EOFException();
        return temp;
	}
	
	/**
	 * Return the pointer within the buffer and move 4 bytes up
	 * @return the offset within the buffer of the read int
	 * @throws IOException tried to move out of bounds
	 */
	public int readAddrInt() throws IOException {
		int temp = inputIndex;
		inputIndex=inputIndex+4;
		if(inputIndex > inputData.length) throw new EOFException();
        return temp;
	}
	
	/**
	 * Return the pointer within the buffer and move 8 bytes up
	 * @return the offset within the buffer of the read long
	 * @throws IOException tried to move out of bounds
	 */
	public int readAddrLong() throws IOException {
		int temp = inputIndex;
		inputIndex=inputIndex+8;
		if(inputIndex > inputData.length) throw new EOFException();
        return temp;
	}
	
	/**
	 * Return the pointer within the buffer and move 2 bytes up
	 * @return the offset within the buffer of the read char
	 * @throws IOException tried to move out of bounds
	 */
	public int readAddrChar() throws IOException {
		int temp = inputIndex;
		inputIndex=inputIndex+2;
		if(inputIndex > inputData.length) throw new EOFException();
        return temp;
	}

	/**
	 * Return the pointer within the buffer and move a byte up
	 * @return the offset within the buffer of the read byte
	 * @throws IOException tried to move out of bounds
	 */
	public int readAddrByte() throws IOException {
		int temp = inputIndex;
		inputIndex=inputIndex+1;
		if(inputIndex > inputData.length) throw new EOFException();
        return temp;
	}
	
	/**
	 * Set the pointer within the buffered data
	 * @param index the offset to point at
	 */
	public void setIndex(int index) {
		inputIndex = index;
	}
	
	/**
	 * Get the current pointer within the buffered data
	 * @return the offset within the data
	 */
	public int getIndex() {
		return inputIndex;
	}
	
	/**
	 * Read a unsigned byte at the current offset of the pointer within the buffer and move the pointer up
	 * @return the read byte as an unsigned byte
	 * @throws IOException tried to read out of bounds
	 */
	public int read() throws IOException {
		int value = inputData[inputIndex]&0xFF;
		inputIndex++;
		if(inputIndex > inputData.length) throw new EOFException();
		return value;
	}
	
	/**
	 * Write a byte to the current buffer position and move the pointer up by 1
	 * @param v the value to write as either a signed or unsigned value
	 * @throws IOException tried to write out of bounds
	 */
	public void write(int v) throws IOException {
		inputData[inputIndex] = (byte) (v&0xFF);
		inputIndex++;
		if(inputIndex > inputData.length) throw new EOFException();
	}
	
	/**
	 * Read 2 bytes at the current offset of the pointer within the buffer and move the pointer up
	 * @return the read bytes as a short
	 * @throws IOException tried to read out of bounds
	 */
	public short getShort(int addr) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
        int ch1 = read();
        int ch2 = read();
        inputIndex=temp;
        return (short)((ch2 << 8) + (ch1 << 0));
	}
	
	/**
	 * Read 4 bytes at the current offset of the pointer within the buffer and move the pointer up
	 * @return the read bytes as an int
	 * @throws IOException tried to read out of bounds
	 */
    public int getInt(int addr) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
        int ch1 = read();
        int ch2 = read();
        int ch3 = read();
        int ch4 = read();
        inputIndex=temp;
        return ((ch4 << 24) + (ch3 << 16) + (ch2 << 8) + (ch1 << 0));
    }
    
	/**
	 * Read 8 bytes at the current offset of the pointer within the buffer and move the pointer up
	 * @return the read bytes as a long
	 * @throws IOException tried to read out of bounds
	 */
    public long getLong(int addr) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
		long result = 0;
		for(int i=0;i<8;i++)
			result = (result | (((long)read()) << i*8L));
        inputIndex=temp;
        
        return result;
    }
    
	/**
	 * Read 2 bytes at the current offset of the pointer within the buffer and move the pointer up
	 * @return the read bytes as a char
	 * @throws IOException tried to read out of bounds
	 */
    public char getChar(int addr) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
        int ch1 = read();
        int ch2 = read();
        inputIndex=temp;
        return (char)((ch2 << 8) + (ch1 << 0));
    }

	/**
	 * Read a byte at the current offset of the pointer within the buffer and move the pointer up
	 * @return the read byte as a byte
	 * @throws IOException tried to read out of bounds
	 */
    public byte getByte(int addr) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
        int ch = read();
        inputIndex=temp;
        return (byte)(ch);
    }
    
    /**
     * Read a string at the given address until a null byte is found and return it
     * @param addr the address to start reading the string
     * @return the read string excluding the null byte
     * @throws IOException tried to read out of bounds
     */
	public String getString(int addr) throws IOException {
		String result = "";
		for(int offset=0;;offset++) {
			byte b = getByte(addr+offset);
			if(b == 0) break;
			result = result + (char)b;
		}
		return result;
	}
	
	/**
	 * Write a string at a given address and zero terminate it
	 * @param str the string to write
	 * @throws IOException tried to write out of bounds
	 */
	public void writeString(String str) throws IOException {
		for(int i=0;i<str.length();i++)
			this.setByte(this.getIndex()+i, (byte)str.charAt(i));
		this.setByte(this.getIndex()+str.length(),(byte) 0);
		this.setIndex(this.getIndex()+str.length()+1);
	}
	
	/**
	 * Read a unicode string until its null terminator at the given address
	 * @param addr the address to start reading at
	 * @return the string that was read
	 * @throws IOException tried to read out of bounds
	 */
	public String getUnicodeString(int addr) throws IOException {
		String result = "";
		for(int offset=0;;offset=offset+2) {
			short b = getShort(addr+offset);
			if(b == 0) break;
			result = result + (char)b;
		}
		return result;
	}
    
	/**
	 * Write 2 bytes at the given address
	 * @param addr the address to write to
	 * @param v the value as an int to write
	 * @throws IOException tried to write out of bounds
	 */
	public void setShort(int addr, int v) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
		write(v >> 0);
		write(v >> 8);
        inputIndex=temp;
	}
	
	/**
	 * Write 4 bytes at the given address
	 * @param addr the address to write to
	 * @param v the value as an int to write
	 * @throws IOException tried to write out of bounds
	 */
    public void setInt(int addr, int v) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
		write(v >> 0);
		write(v >> 8);
		write(v >> 16);
		write(v >> 24);
        inputIndex=temp;
    }
    
	/**
	 * Write 8 bytes at the given address
	 * @param addr the address to write to
	 * @param v the value as an long to write
	 * @throws IOException tried to write out of bounds
	 */
    public void setLong(int addr, long v) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
		for(int i=0;i<8;i++)
			write((int)(v >> 8*i));
        inputIndex=temp;
    }
    
	/**
	 * Write 2 bytes at the given address
	 * @param addr the address to write to
	 * @param v the value as an int to write
	 * @throws IOException tried to write out of bounds
	 */
    public void setChar(int addr, char v) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
		write(v >> 0);
		write(v >> 8);
        inputIndex=temp;
    }

	/**
	 * Write one byte at the given address
	 * @param addr the address to write to
	 * @param v the value as an int to write
	 * @throws IOException tried to write out of bounds
	 */
    public void setByte(int addr, byte v) throws IOException {
		int temp = inputIndex;
		inputIndex = addr;
		write(v);
        inputIndex=temp;
    }

}
