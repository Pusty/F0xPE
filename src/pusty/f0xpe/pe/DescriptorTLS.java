package pusty.f0xpe.pe;

import java.io.IOException;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.location.Address;
import pusty.f0xpe.pe.ExecutableReader;

/** 
 * A class trying to abstract the Thread Local Storage (TLS) Directory 
 * <br>Reference: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-tls-directory
 */
public class DescriptorTLS extends ReadableObject{

	/** The architecture dependent IMAGE_TLS_DIRECTORY structure of this abstraction */
	protected IMAGE_TLS_DIRECTORY tls;
	/** The parsed callbacks */
	protected Address[] callbacks;
	
	/**
	 * Create a new Thread Local Storage Structure at the given index the reader is at
	 * @param reader the reader to parse the import table at
	 * @throws Exception something went wrong
	 */
	public DescriptorTLS(ExecutableReader reader)
			throws Exception {
		super(reader);
	}

	@Override
	public void read(ExecutableStream s) throws Exception {
		if(reader.is32bit()) {
			tls = new IMAGE_TLS_DIRECTORY32(reader);
			int addr = reader.addr2offset(tls.getAddressOfCallBacks());
			int offset = 0;
			int size = 0;
			for(offset=0;reader.getStream().getInt(addr+offset) != 0;offset+=4,size++);
			callbacks = new Address[size];
			for(offset=0;offset < size*4;offset+=4)
				callbacks[offset/4] = new Address(reader.getStream().getInt(addr+offset));
		} else {
			tls = new IMAGE_TLS_DIRECTORY64(reader);
			int addr = reader.addr2offset(tls.getAddressOfCallBacks());
			int offset = 0;
			int size = 0;
			for(offset=0;reader.getStream().getLong(addr+offset) != 0;offset+=8,size++);
			callbacks = new Address[size];
			for(offset=0;offset < size*8;offset+=8)
				callbacks[offset/8] = new Address(reader.getStream().getLong(addr+offset));
		}
	}
	
	/**
	 * Returns the callbacks noted in the TLS (addresses not RVAs or offsets)
	 * @return the callbacks of the TLS directory
	 */
	public Address[] getTLSCallbacks() {
		return callbacks;
	}
	
	/**
	 * Return the architecture dependent IMAGE_TLS_DIRECTORY structure
	 * @return
	 */
	public IMAGE_TLS_DIRECTORY getTLS() {
		return tls;
	}

	/**
	 * A class representing the generic IMAGE_TLS_DIRECTORY structure
	 * <br>NOTE: 32bit and 64bit have different specific implementations and sizes
	 */
	public static abstract class IMAGE_TLS_DIRECTORY extends ReadableObject {

		/** Starting address (virtual address) of the raw data */
		protected int StartAddressOfRawData;
		/** Ending address (virtual address) of the raw data */
		protected int EndAddressOfRawData;
		/** Address of the index to receive */
		protected int AddressOfIndex;
		/** Pointer to an zero terminated array of TLS Callback functions */
		protected int AddressOfCallBacks;
		/** The amount of zero byte fill after the actual TLS data */
		protected int SizeOfZeroFill;
		/** Characteristics for the TLS Directory */
		protected int Characteristics;
		  
		/**
		 * Create a IMAGE_TLS_DIRECTORY structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_TLS_DIRECTORY(ExecutableReader reader) throws Exception {
			super(reader);
		}
		
		/**
		 * Return the starting virtual address of the TLS data. 
		 * @return the start address of the raw TLS data
		 */
		public abstract Address getStartAddressOfRawData();
		
		/**
		 * Set the starting virtual address of the TLS data
		 * @param startAddressOfRawData the new start address of the raw TLS data
		 */
		public abstract void setStartAddressOfRawData(Address startAddressOfRawData);
		
		/**
		 * Return the ending virtual address of the TLS data. After this only the zero fill should follow within the TLS directory
		 * @return the last address of the raw TLS data
		 */
		public abstract Address getEndAddressOfRawData();
		
		/**
		 * Set the ending virtual address of the TLS data
		 * @param startAddressOfRawData the new last address of the raw TLS data
		 */
		public abstract void setEndAddressOfRawData(Address endAddressOfRawData);
		
		/**
		 * Return the virtual address that will contain the TLS index written by the loader.
		 * @return the address of the index
		 */
		public abstract Address getAddressOfIndex();
		
		/**
		 * Set the virtual address that will contain the TLS index written by the loader.
		 * @param addressOfIndex the new address of the index
		 */
		public abstract void setAddressOfIndex(Address addressOfIndex);
		
		/**
		 * Return the virtual address of the zero terminated array of TLS Callback functions.
		 * @return the address of the first TLS callback
		 */
		public abstract Address getAddressOfCallBacks();
		
		/**
		 * Set the virtual address of the zero terminated array of TLS Callback functions.
		 * @param addressOfCallBacks the new address of the TLS Callback array
		 */
		public abstract void setAddressOfCallBacks(Address addressOfCallBacks);


		/**
		 * Return the amount of zero byte fillings contained in the TLS Directory
		 * @return the amount of zero byte filling
		 */
		public int getSizeOfZeroFill() {
			try {
				return reader.getStream().getInt(SizeOfZeroFill);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the amount of zero byte filling contained in the TLS Directory
		 * @param sizeOfZeroFill the new amount of zero byte filling
		 */
		public void setSizeOfZeroFill(int sizeOfZeroFill) {
			try {
				reader.getStream().setInt(SizeOfZeroFill, sizeOfZeroFill);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the characteristics of the TLS Directory
		 * @return the characteristics of this directory
		 */
		public int getCharacteristics() {
			try {
				return reader.getStream().getInt(Characteristics);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
		
		/**
		 * Set the characteristics of the TLS Directory
		 * @param characteristics the new characteristics of this directory
		 */
		public void setCharacteristics(int characteristics) {
			try {
				reader.getStream().setInt(Characteristics, characteristics);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}
		
	}

	/**
	 * A class for representing the 32bit implementation of the IMAGE_TLS_DIRECTORY structure
	 */
	public static class IMAGE_TLS_DIRECTORY32 extends IMAGE_TLS_DIRECTORY {

		/**
		 * Create a IMAGE_TLS_DIRECTORY32 structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_TLS_DIRECTORY32(ExecutableReader reader) throws Exception {
			super(reader);
		}
		
		@Override
		public void read(ExecutableStream s) throws Exception {
			StartAddressOfRawData = s.readAddrInt();
			EndAddressOfRawData   = s.readAddrInt();
			AddressOfIndex        = s.readAddrInt();
			AddressOfCallBacks    = s.readAddrInt();
			SizeOfZeroFill        = s.readAddrInt();
			Characteristics       = s.readAddrInt();
		}
		
		/**
		 * Return the raw 32bit starting address from the directory
		 * @return the starting raw address of this directory
		 */
		public int getStartAddressOfRawData32() {
			try {
				return reader.getStream().getInt(StartAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 32bit starting address of this directory
		 * @param startAddressOfRawData the new raw starting address of this directory
		 */
		public void setStartAddressOfRawData32(int startAddressOfRawData) {
			try {
				reader.getStream().setInt(StartAddressOfRawData, startAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getStartAddressOfRawData() {
			return new Address(getStartAddressOfRawData32());
		}

		@Override
		public void setStartAddressOfRawData(Address startAddressOfRawData) {
			setStartAddressOfRawData32(startAddressOfRawData.getAddr32());
		}

		
		/**
		 * Return the raw 32bit ending address from the directory
		 * @return the raw ending address of this directory
		 */
		public int getEndAddressOfRawData32() {
			try {
				return reader.getStream().getInt(EndAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 32bit ending address of this directory
		 * @param endAddressOfRawData the new raw ending address of this directory
		 */
		public void setEndAddressOfRawData32(int endAddressOfRawData) {
			try {
				reader.getStream().setInt(EndAddressOfRawData, endAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getEndAddressOfRawData() {
			return new Address(getEndAddressOfRawData32());
		}

		@Override
		public void setEndAddressOfRawData(Address endAddressOfRawData) {
			setEndAddressOfRawData32(endAddressOfRawData.getAddr32());
		}
		
		/**
		 * Return the raw 32bit address of the TLS index
		 * @return the raw TLS index address
		 */
		public int getAddressOfIndex32() {
			try {
				return reader.getStream().getInt(AddressOfIndex);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 32bit address of the TLS index
		 * @param addressOfIndex the new raw TLS index address
		 */
		public void setAddressOfIndex32(int addressOfIndex) {
			try {
				reader.getStream().setInt(AddressOfIndex, addressOfIndex);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getAddressOfIndex() {
			return new Address(getAddressOfIndex32());
		}

		@Override
		public void setAddressOfIndex(Address addressOfIndex) {
			setAddressOfIndex32(addressOfIndex.getAddr32());
		}
		
		/**
		 * Return the raw 32bit address of the array of TLS callbacks
		 * @return the raw address of the array of callbacks
		 */
		public int getAddressOfCallBacks32() {
			try {
				return reader.getStream().getInt(AddressOfCallBacks);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 32bit address of the array of TLS callbacks.
		 * @param addressOfCallBacks the new raw address of the array of callbacks
		 */
		public void setAddressOfCallBacks32(int addressOfCallBacks) {
			try {
				reader.getStream().setInt(AddressOfCallBacks, addressOfCallBacks);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getAddressOfCallBacks() {
			return new Address(getAddressOfCallBacks32());
		}

		@Override
		public void setAddressOfCallBacks(Address addressOfCallBacks) {
			setAddressOfCallBacks32(addressOfCallBacks.getAddr32());
		}


	}
	
	/**
	 * A class for representing the 32bit implementation of the IMAGE_TLS_DIRECTORY structure
	 */
	public static class IMAGE_TLS_DIRECTORY64 extends IMAGE_TLS_DIRECTORY {

		/**
		 * Create a IMAGE_TLS_DIRECTORY64 structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_TLS_DIRECTORY64(ExecutableReader reader) throws Exception {
			super(reader);
		}
		
		@Override
		public void read(ExecutableStream s) throws Exception {
			StartAddressOfRawData = s.readAddrLong();
			EndAddressOfRawData   = s.readAddrLong();
			AddressOfIndex        = s.readAddrLong();
			AddressOfCallBacks    = s.readAddrLong();
			SizeOfZeroFill        = s.readAddrInt();
			Characteristics       = s.readAddrInt();
		}
		
		/**
		 * Return the raw 64bit starting address from the directory
		 * @return the raw starting address of this directory
		 */
		public long getStartAddressOfRawData64() {
			try {
				return reader.getStream().getLong(StartAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 64bit starting address of this directory
		 * @param startAddressOfRawData the new raw starting address of this directory
		 */
		public void setStartAddressOfRawData64(long startAddressOfRawData) {
			try {
				reader.getStream().setLong(StartAddressOfRawData, startAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getStartAddressOfRawData() {
			return new Address(getStartAddressOfRawData64());
		}

		@Override
		public void setStartAddressOfRawData(Address startAddressOfRawData) {
			setStartAddressOfRawData64(startAddressOfRawData.getAddr64());
		}

		
		/**
		 * Return the raw 64bit ending address from the directory
		 * @return the raw ending address of this directory
		 */
		public long getEndAddressOfRawData64() {
			try {
				return reader.getStream().getLong(EndAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 64bit ending address of this directory
		 * @param endAddressOfRawData the new raw ending address of this directory
		 */
		public void setEndAddressOfRawData64(long endAddressOfRawData) {
			try {
				reader.getStream().setLong(EndAddressOfRawData, endAddressOfRawData);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getEndAddressOfRawData() {
			return new Address(getEndAddressOfRawData64());
		}

		@Override
		public void setEndAddressOfRawData(Address endAddressOfRawData) {
			setEndAddressOfRawData64(endAddressOfRawData.getAddr64());
		}
		
		/**
		 * Return the raw 64bit address of the TLS index
		 * @return the raw TLS index address
		 */
		public long getAddressOfIndex64() {
			try {
				return reader.getStream().getLong(AddressOfIndex);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 64bit address of the TLS index
		 * @param addressOfIndex the new raw TLS index address
		 */
		public void setAddressOfIndex64(long addressOfIndex) {
			try {
				reader.getStream().setLong(AddressOfIndex, addressOfIndex);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getAddressOfIndex() {
			return new Address(getAddressOfIndex64());
		}

		@Override
		public void setAddressOfIndex(Address addressOfIndex) {
			setAddressOfIndex64(addressOfIndex.getAddr64());
		}
		
		/**
		 * Return the raw 64bit address of the array of TLS callbacks
		 * @return the raw address of the array of callbacks
		 */
		public long getAddressOfCallBacks64() {
			try {
				return reader.getStream().getLong(AddressOfCallBacks);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the raw 64bit address of the array of TLS callbacks.
		 * @param addressOfCallBacks the new raw address of the array of callbacks
		 */
		public void setAddressOfCallBacks64(long addressOfCallBacks) {
			try {
				reader.getStream().setLong(AddressOfCallBacks, addressOfCallBacks);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		@Override
		public Address getAddressOfCallBacks() {
			return new Address(getAddressOfCallBacks64());
		}

		@Override
		public void setAddressOfCallBacks(Address addressOfCallBacks) {
			setAddressOfCallBacks64(addressOfCallBacks.getAddr64());
		}


	}
}
