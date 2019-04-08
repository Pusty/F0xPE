package pusty.f0xpe.payload;

import java.io.File;
import java.io.FileInputStream;

import pusty.f0xpe.ExecutableStream;

/**
 * A Payload that is initialized with a immutable array and proper read and write functionality.
 */
public class EditablePayload extends Payload{
	
	/**
	 * Create a new editable payload with a given start content which also determines the maximum size
	 * @param d the data of this payload instance
	 */
	public EditablePayload(byte[] d) {		
		super(d);
	}
	
	
	
	/**
	 * Read a byte at index from the payload. Return -1 if failed to read at index.
	 * @param index the index to read from
	 * @return a byte read at index within the payload
	 */
	public byte getByte(int index) {
		try {
			return new ExecutableStream(payload).getByte(index);
		} catch (Exception e) {
			e.printStackTrace();
		} return -1;
	}
	
	/**
	 * Read a short at index from the payload. Return -1 if failed to read at index.
	 * @param index the index to read from
	 * @return a short read at index within the payload
	 */
	public short getShort(int index) {
		try {
			return new ExecutableStream(payload).getShort(index);
		} catch (Exception e) {
			e.printStackTrace();
		} return -1;
	}	
	
	/**
	 * Read a int at index from the payload. Return -1 if failed to read at index.
	 * @param index the index to read from
	 * @return a int read at index within the payload
	 */
	public int getInt(int index) {
		try {
			return new ExecutableStream(payload).getInt(index);
		} catch (Exception e) {
			e.printStackTrace();
		} return -1;
	}
	
	/**
	 * Read a long at index from the payload. Return -1 if failed to read at index.
	 * @param index the index to read from
	 * @return a long read at index within the payload
	 */
	public long getLong(int index) {
		try {
			return new ExecutableStream(payload).getLong(index);
		} catch (Exception e) {
			e.printStackTrace();
		} return -1;
	}
	
	/**
	 * Write a byte at index within the payload.
	 * @param index the index to write to
	 * @param value the data to write at index within the payload
	 */
	public void setByte(int index, byte value) {
		try {
			new ExecutableStream(payload).setByte(index, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Write a short at index within the payload.
	 * @param index the index to write to
	 * @param value the data to write at index within the payload
	 */
	public void setShort(int index, short value) {
		try {
			new ExecutableStream(payload).setShort(index, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Write a int at index within the payload.
	 * @param index the index to write to
	 * @param value the data to write at index within the payload
	 */
	public void setInt(int index, int value) {
		try {
			new ExecutableStream(payload).setInt(index, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Write a long at index within the payload.
	 * @param index the index to write to
	 * @param value the data to write at index within the payload
	 */
	public void setLong(int index, long value) {
		try {
			new ExecutableStream(payload).setLong(index, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	/**
	 * Search for a specific byte value within the payload and return the index
	 * @param find the value to search for
	 * @return the index of the first occurrence of the search value. -1 if not found
	 */
	public int findByte(byte find) {
		return findByte(find, 0, payload.length);
	}
	
	/**
	 * Search for a specific byte value within the payload within a specific range from start to stop index
	 * @param find the value to search for
	 * @param start the start index to start searching from (inclusive)
	 * @param end the stop index indicating the end (exclusive)
	 * @return the index of the first occurrence within the specified range. -1 if not found or in case of any error
	 */
	public int findByte(byte find,int start, int end) {
		final int SEARCHSIZE = 1; //a byte is one byte in size (duh)
		try {
			ExecutableStream ex = new ExecutableStream(payload);
			for (int i = start; i < end-SEARCHSIZE+1; i++) {
					if(ex.getByte(i)==find)
						return i;		
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return -1;
	}
	
	
	
	/**
	 * Search for a specific short value within the payload and return the index
	 * @param find the value to search for
	 * @return the index of the first occurrence of the search value. -1 if not found
	 */
	public int findShort(short find) {
		return findShort(find, 0, payload.length);
	}
	
	/**
	 * Search for a specific short value within the payload within a specific range from start to stop index
	 * @param find the value to search for
	 * @param start the start index to start searching from (inclusive)
	 * @param end the stop index indicating the end (exclusive)
	 * @return the index of the first occurrence within the specified range. -1 if not found or in case of any error
	 */
	public int findShort(short find,int start, int end) {
		final int SEARCHSIZE = 2; //a short is 2 bytes in size
		try {
			ExecutableStream ex = new ExecutableStream(payload);
			for (int i = start; i < end-SEARCHSIZE+1; i++) {
					if(ex.getShort(i)==find)
						return i;		
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return -1;
	}
	
	/**
	 * Search for a specific int value within the payload and return the index
	 * @param find the value to search for
	 * @return the index of the first occurrence of the search value. -1 if not found
	 */
	public int findInt(int find) {
		return findInt(find, 0, payload.length);
	}
	
	/**
	 * Search for a specific int value within the payload within a specific range from start to stop index
	 * @param find the value to search for
	 * @param start the start index to start searching from (inclusive)
	 * @param end the stop index indicating the end (exclusive)
	 * @return the index of the first occurrence within the specified range. -1 if not found or in case of any error
	 */
	public int findInt(int find,int start, int end) {
		final int SEARCHSIZE = 4; //an int is 4 bytes in size
		try {
			ExecutableStream ex = new ExecutableStream(payload);
			for (int i = start; i < end-SEARCHSIZE+1; i++) {
					if(ex.getInt(i)==find)
						return i;		
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return -1;
	}
	
	/**
	 * Search for a specific long value within the payload and return the index
	 * @param find the value to search for
	 * @return the index of the first occurrence of the search value. -1 if not found
	 */
	public int findLong(long find) {
		return findLong(find, 0, payload.length);
	}
	
	/**
	 * Search for a specific long value within the payload within a specific range from start to stop index
	 * @param find the value to search for
	 * @param start the start index to start searching from (inclusive)
	 * @param end the stop index indicating the end (exclusive)
	 * @return the index of the first occurrence within the specified range. -1 if not found or in case of any error
	 */
	public int findLong(long find,int start, int end) {
		final int SEARCHSIZE = 8; //a long is 8 bytes in size
		try {
			ExecutableStream ex = new ExecutableStream(payload);
			for (int i = start; i < end-SEARCHSIZE+1; i++) {
					if(ex.getLong(i)==find)
						return i;		
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return -1;
	}


	/**
	 * Create an EditablePayload based on any other payload. (note that the data of the payload is cloned as well)
	 * @param p the payload to create an editable clone of
	 * @return the cloned editable version of the orignal payload
	 */
	public static EditablePayload clone(Payload p) {
		return new EditablePayload(p.getPayload().clone());
	}
	
	/**
	 * Create an EditablePayload based on the content of a file.
	 * @param file the file to read and turn into a payload
	 * @return the read payload, null if an error accured
	 */
	public static EditablePayload fromFile(File file) {
		try {
			FileInputStream fis = new FileInputStream(file);
			byte[] data = new byte[fis.available()];
			fis.read(data);
			fis.close();
			EditablePayload payload = new EditablePayload(data);
			return payload;
		} catch (Exception e) {
			e.printStackTrace();
		} return null;
	}
	
	/**
	 * Create an EditablePayload from a hex string
	 * @param hex the hex string to parse
	 * @return the resulting payload
	 */
	public static EditablePayload fromHexString(String hex) {
		if(hex.length()%2 != 0) {
			System.err.println("Can't work with odd length hex string");
			return null;
		}
		if(hex.length() == 0) {
			System.err.println("Can't work with empty string");
			return null;
		}
		byte[] data = new byte[hex.length()/2];
		for(int i=0;i<data.length;i++)
			data[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
		
		return new EditablePayload(data);
	}
}
