package pusty.f0xpe.payload;

/** A abstract immutable Payload containing a fixed amount of bytes. */
public abstract class Payload {
	
	/** The data of this Payload */
	protected final byte[] payload;
	
	/**
	 * Create a payload with the given data
	 * @param d the content of this payload
	 */
	public Payload(byte[] d) {		
		payload = d;
	}
	
	/**
	 * Get the size of this this payload
	 * @return the size of the data of this payload
	 */
	public int getSize() {
		return payload.length;
	}
	
	/**
	 * Get the data of this playload
	 * @return the payload itself
	 */
	public byte[] getPayload() {
		return payload;
	}
	
	
}
