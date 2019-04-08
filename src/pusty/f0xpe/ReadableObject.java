package pusty.f0xpe;

import java.io.IOException;

import pusty.f0xpe.pe.ExecutableReader;

/**
 * Abstract class for defining structures within ExecutableStreams
 */
public abstract class ReadableObject {

	//Offset in memory of this instance
	private int offset = 0;
	//Size of this instance
	private int sizeof = 0;

	/**
	 * The reader object of this instance
	 */
	protected ExecutableReader reader;
	
	/**
	 * Create a new Object that's readable from a ExecutableReader object
	 * <br> NOTE: The constructor starts the reading of the object and reading ReadableObjects is NOT THREAD SAFE
	 * @param reader the reader to read from
	 * @param s the stream to read from (normally the stream is from the reader itself)
	 * @throws Exception something went wrong while reading the object
	 */
	public ReadableObject(ExecutableReader reader)
			throws Exception {
		this.reader = reader;
		this.readSuper(reader.getStream());
	}
	/**
	 * Calls the read function of each ReadableObject within wrapper functions to measure size and offset
	 * <br>NOTE: Reading ReadableObjects is NOT THREAD SAFE
	 * @param s the stream to read from
	 * @throws Exception reading the object failed
	 */
	public void readSuper(ExecutableStream s) throws Exception {
		sizeof = s.getIndex();
		offset = s.getIndex();
		//
		read(s);
		//
		sizeof=s.getIndex()-sizeof;
	}
	
	/**
	 * Reads the object from an ExecutableStream
	 * <br>NOTE: Reading ReadableObjects is NOT THREAD SAFE
	 * @param s the stream to read from
	 * @throws Exception something went wrong while reading
	 */
	public abstract void read(ExecutableStream s) throws Exception;
	
	/**
	 * Returns whether is object empty (throws an error when object can't be read, doesn't stop execution of code)
	 * @return whether is object contains just zero bytes or not
	 */
	public boolean isEmpy() {
		for(int i=0;i<sizeof;i++)
			try {
				if(reader.getStream().getByte(offset+i) != (byte)0) return false;
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		return true;
	}
	/**
	 * Returns the size of the object
	 * @return the amount of bytes read
	 */
	public int sizeof() {
		return sizeof;
	}
	/**
	 * Returns the offset of this object
	 * @return the starting offset within the file/byte stream of this object
	 */
	public int offset() {
		return offset;
	}
	
	/**
	 * Calculate the offset by initializing a dummy object and reseting the index
	 * <br>NOTE: NOT THREAD SAFE
	 * <br>NOTE: MAY NOT work for all ReadableObjects
	 * @param obj the dummy objects
	 * @return the size of the dummy objects
	 */
	public static int sizeof(ReadableObject obj) {
		obj.reader.getStream().setIndex(obj.offset);
		return obj.sizeof;
	}
}
