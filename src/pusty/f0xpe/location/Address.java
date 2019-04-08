package pusty.f0xpe.location;

/**
 * A Wrapper for Addresses (RVAs and absolute)
 */
public class Address {
	private long addr64 = 0;
	
	/**
	 * Create a Address with size depending on inputed object (integer=>32bit,long=>64bit,other=>error)
	 * @param v address
	 */
	public Address(Object object) {
		this(object.getClass() == Integer.class?(int)object:(long)object);
	}	
	/**
	 * Create 32bit Address with given content
	 * @param v address
	 */
	public Address(int v) {
		addr64 = (long)v;
	}
	/**
	 * Create 64bit Address with given content
	 * @param v address
	 */
	public Address(long v) {
		addr64 = v;
	}
	/**
	 * Return Address
	 * @return address in long (64bit) format
	 */
	public long getAddr64() {
		return addr64;
	}
	/**
	 * Return Address
	 * @return address in integer (32bit) format
	 */
	public int getAddr32() {
		return (int)(addr64&0xFFFFFFFFL);
	}
	/**
	 * Check if address is zero
	 * @return check if address is 0
	 */
	public boolean isNull() {
		return addr64==0;
	}
	/**
	 * Add addresses together, not unsigned for 64bit nor overflowing for 32bit
	 * @param addr address to add to this
	 * @return resulting address
	 */
	public Address add(Address addr) {
		Address result = new Address(this.getAddr64());
		result.addr64 = result.addr64 + addr.addr64;
		return result;
	}
	/**
	 * Subtracts addresses, not unsigned for 64bit nor overflowing for 32bit
	 * @param addr address to subtract from this
	 * @return resulting address
	 */
	public Address sub(Address addr) {
		Address result = new Address(this.getAddr64());
		result.addr64 = result.addr64 - addr.addr64;
		return result;
	}
}
