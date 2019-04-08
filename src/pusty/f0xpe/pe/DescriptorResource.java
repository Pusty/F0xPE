package pusty.f0xpe.pe;

import java.io.IOException;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.pe.ExecutableReader;

/** 
 * A class representing the PE Resource Data Structure
 * <br>Reference: https://msdn.microsoft.com/en-us/library/ms809762.aspx
 */
public class DescriptorResource extends ReadableObject{

	/** The root IMAGE_RESOURCE_DIRECTORY */
	protected IMAGE_RESOURCE_DIRECTORY root;
	
	/**
	 * Create a new Resource Data Structure at the given index the reader is at
	 * @param reader the reader to parse the resource data at
	 * @throws Exception something went wrong
	 */
	public DescriptorResource(ExecutableReader reader)
			throws Exception {
		super(reader);
	}
	

	@Override
	public void read(ExecutableStream s) throws Exception {
		root = new IMAGE_RESOURCE_DIRECTORY(reader);
		root.parse();
	}
	
	/**
	 * Return the root IMAGE_RESOURCE_DIRECTORY
	 * @return the IMAGE_RESOURCE_DIRECTORY that all resources originate in
	 */
	public IMAGE_RESOURCE_DIRECTORY getRoot() {
		return root;
	}

	/** 
	 * A class for representing the IMAGE_RESOURCE_DIRECTORY structure (which itself represents a directory of resource entries) 
	 */
	public static class IMAGE_RESOURCE_DIRECTORY extends ReadableObject {
		
		/** Possible characteristics of this resource, not used */
		protected int Characteristics;
		/** Time indicating the creation of this resource */
		protected int TimeDateStamp;
		/** Possible Major Version of this resource, not used */
		protected int MajorVersion;
		/** Possible Minor Version of this resource, not used */
		protected int MinorVersion;
		/** The number of resource entries that use names and are associated with this directory */
		protected int NumberOfNamedEntries;
		/** The number of resource entries that use ids and are associated with this directory */
		protected int NumberOfIdEntries;
		
		/** The resource entries of this directory */
		protected IMAGE_RESOURCE_DIRECTORY_ENTRY[] entries;
		
		/**
		 * Create a IMAGE_RESOURCE_DIRECTORY structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_RESOURCE_DIRECTORY(ExecutableReader reader) throws Exception {
			super(reader);
		}

		@Override
		public void read(ExecutableStream s) throws Exception {
		    Characteristics = s.readAddrInt();
		    TimeDateStamp = s.readAddrInt();
		    MajorVersion = s.readAddrShort();
		    MinorVersion = s.readAddrShort();
		    NumberOfNamedEntries = s.readAddrShort();
		    NumberOfIdEntries = s.readAddrShort();
		}
		
		/**
		 * A function for parsing the resource entries of this directory
		 * @throws Exception something went wrong while trying to parse
		 */
		public void parse() throws Exception { 
			//Different function than read(...) to not modify size of structure
			entries = new IMAGE_RESOURCE_DIRECTORY_ENTRY[this.getNumberOfEntries()];
		    for(int i=0;i<entries.length;i++) {
		    	entries[i] = new IMAGE_RESOURCE_DIRECTORY_ENTRY(reader);
		    	entries[i].parse();
		    }
		}

		/**
		 * Return the resource entries of this directory 
		 * @return the resources associated with this directory
		 */
		public IMAGE_RESOURCE_DIRECTORY_ENTRY[] getEntires() {
			return entries;
		}
		
		/**
		 * Return the possible characteristics of this resource, the field is not actually used 
		 * @return the characteristics of this resource
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
		 * Set the possible characteristics of this resource, the field is not actually used
		 * @param characteristics the new characteristics of this resource
		 */
		public void setCharacteristics(int characteristics) {
			try {
				reader.getStream().setInt(Characteristics, characteristics);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the time stamp indicating the creation of this resource
		 * @return the time this resource was created
		 */
		public int getTimeDateStamp() {
			try {
				return reader.getStream().getInt(TimeDateStamp);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
		
		/**
		 * Set the time stamp that indicates when this resource was created
		 * @param timeDateStamp the new time stamp of this resource
		 */
		public void setTimeDateStamp(int timeDateStamp) {
			try {
				reader.getStream().setInt(TimeDateStamp, timeDateStamp);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the major version of this resource, this field is not actually used
		 * @return the major version of this resource
		 */
		public short getMajorVersion() {
			try {
				return reader.getStream().getShort(MajorVersion);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the major version of this resource, this field is not actually used
		 * @param majorVersion the new major version of this resource
		 */
		public void setMajorVersion(short majorVersion) {
			try {
				reader.getStream().setShort(MajorVersion, majorVersion);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the minor version of this resource, this field is not actually used
		 * @return the minor version of this resource
		 */
		public short getMinorVersion() {
			try {
				return reader.getStream().getShort(MinorVersion);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}


		/**
		 * Set the minor version of this resource, this field is not actually used
		 * @param minorVersion the new minor version of this resource
		 */
		public void setMinorVersion(short minorVersion) {
			try {
				reader.getStream().setShort(MinorVersion, minorVersion);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the amount of entries associated to this directory that are named
		 * @return the amount of named entries
		 */
		public short getNumberOfNamedEntries() {
			try {
				return reader.getStream().getShort(NumberOfNamedEntries);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the amount of entries that are identified by name
		 * @param numberOfNamedEntries the new amount of entries that use names
		 */
		public void setNumberOfNamedEntries(short numberOfNamedEntries) {
			try {
				reader.getStream().setShort(NumberOfNamedEntries, numberOfNamedEntries);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the amount of entries associated to this directory that use ids
		 * @return the amount of entries that use ids
		 */
		public short getNumberOfIdEntries() {
			try {
				return reader.getStream().getShort(NumberOfIdEntries);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the amount of entries that are identified by id
		 * @param numberOfNamedEntries the new amount of entries that use ids
		 */
		public void setNumberOfIdEntries(short numberOfIdEntries) {
			try {
				reader.getStream().setShort(NumberOfIdEntries, numberOfIdEntries);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}
		
		/**
		 * Return the total amount of entries of this directory
		 * @return the amount of entries associated with this directory
		 */
		public int getNumberOfEntries() {
			return getNumberOfIdEntries() + getNumberOfNamedEntries();
		}

	}
	
	/** 
	 * A class for representing the IMAGE_RESOURCE_DIRECTORY_ENTRY structure (which itself represents an entry in a resource directory) 
	 */
	public static class IMAGE_RESOURCE_DIRECTORY_ENTRY extends ReadableObject {
		
		/** A bitmask used for seperating type of this entry and method of identification  */
		public static int IMAGE_ORDINAL_FLAG32 = 0x80000000;
		
		/**
		 * Contains either the ID of this entry or the name.
		 * If the highest bit (0x80000000) is zero it's an id, if not it's a pointer to a structure containing the name
		 */
	    protected int Name;
	    
	    
	    /**
	     * Contains either an offset to a IMAGE_RESOURCE_DATA_ENTRY or IMAGE_RESOURCE_DIRECTORY.
	     * If the highest bit (0x80000000) is zero it's a data entry, if not it's a sub directory
	     */
	    protected int OffsetToData;
	    
	    /** Contains this entry as a data entry after parsing */
	    protected IMAGE_RESOURCE_DATA_ENTRY data_entry = null;
	    
	    /** Contains this entry as a directory  after parsing */
	    protected IMAGE_RESOURCE_DIRECTORY  dir_entry  = null;
	    
	    
		/**
		 * Create a IMAGE_RESOURCE_DIRECTORY_ENTRY structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_RESOURCE_DIRECTORY_ENTRY(ExecutableReader reader) throws Exception {
			super(reader);
		}

		@Override
		public void read(ExecutableStream s) throws Exception {
		    Name = s.readAddrInt();
		    OffsetToData = s.readAddrInt();
		}
		
		/**
		 * Return whether this directory entry is an directory itself
		 * @return if this entry is an directory
		 */
		public boolean isDirectory() {
			return (getOffsetToData()&IMAGE_ORDINAL_FLAG32)!=0;
		}
		
		/**
		 * Parse the content of this directory entry
		 * @throws Exception something went wrong while trying to parse this directory entry
		 */
		public void parse() throws Exception {
			int tmp = reader.getStream().getIndex();
			int offset = (getOffsetToData()&~IMAGE_ORDINAL_FLAG32)+reader.getOptionalHeader().getResourceOffset();
			reader.getStream().setIndex(offset);
			if(isDirectory()) {
				dir_entry = new IMAGE_RESOURCE_DIRECTORY(reader);
				dir_entry.parse();
			}else{
				data_entry = new IMAGE_RESOURCE_DATA_ENTRY(reader);
			}
			reader.getStream().setIndex(tmp);
		}
		
		/**
		 * Return this entry as a directory, return null if it's not a directory
		 * <br>NOTE: Needs to be parsed before hand
		 * @return this entry as a directory
		 */
		public IMAGE_RESOURCE_DIRECTORY getDir() {
			if(!isDirectory()) return null;
			return dir_entry;
		}
		
		/**
		 * Return this entry as a data entry, return null if it's a directory
		 * <br>NOTE: Needs to be parsed before hand
		 * @return this entry as a data entry
		 */
		public IMAGE_RESOURCE_DATA_ENTRY getData() {
			if(isDirectory()) return null;
			return data_entry;
		}
		
		/**
		 * Return whether this entry is identified by id
		 * @return if this directory entry uses an id
		 */
		public boolean isOrdinal() {
			return (getName()&IMAGE_ORDINAL_FLAG32)==0;
		}
		
		/**
		 * Return the id of this entry, -1 if it uses a name for identification
		 * @return the id of this entry
		 */
		public int getID() {
			if(!isOrdinal()) return -1;
			return getName();
		}
		
		/**
		 * Return the name of this entry as a Java String, null if it uses an id for identification
		 * @return the name of this resource
		 */
		public String getNameStr() {
			if(isOrdinal()) return null;
			int offset = (getName()&~IMAGE_ORDINAL_FLAG32);
			offset = offset + reader.getOptionalHeader().getResourceOffset();
			try {
				int size = reader.getStream().getShort(offset); //This is a IMAGE_RESOURCE_DIR_STRING_U structure
				char[] str = new char[size];                //I don't think it's necessary to create that as a new class
				for(int i=0;i<size;i++)
					str[i] = (char) reader.getStream().getShort(offset+2+2*i);
				return new String(str);
			} catch (IOException e) {
				e.printStackTrace();
				return null;
			}
		} 
		
		/**
		 * The value of the Name field of this directory entry
		 * @return the value of the Name field
		 */
		public int getName() {
			try {
				return reader.getStream().getInt(Name);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the value of the Name field of this directory entry
		 * @param name the new value of the Name field
		 */
		public void setName(int name) {
			try {
				reader.getStream().setInt(Name, name);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Get the value of the OffsetToData field of this directory entry
		 * @return the value of the OffsetToData field
		 */
		public int getOffsetToData() {
			try {
				return reader.getStream().getInt(OffsetToData);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the value of the OffsetToData field of this directory entry
		 * @param offsetToData the new value of the OffsetToData field
		 */
		public void setOffsetToData(int offsetToData) {
			try {
				reader.getStream().setInt(OffsetToData, offsetToData);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

	}
	
	/** 
	 * A class for representing the IMAGE_RESOURCE_DATA_ENTRY structure (which itself represents a resource) 
	 * <br>Reference: https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
	 */
	public static class IMAGE_RESOURCE_DATA_ENTRY extends ReadableObject {

		/** RVA to the actual data of this entry */
	    protected int OffsetToData;
	    /** Size of the data of this entry */
	    protected int Size;
	    /** Unicode codepage used for decoding Unicode Strings in the resource */
	    protected int CodePage;
	    /** Reserved value, should be 0 */
	    protected int Reserved;
	    
		/**
		 * Create a IMAGE_RESOURCE_DATA_ENTRY structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_RESOURCE_DATA_ENTRY(ExecutableReader reader) throws Exception {
			super(reader);
		}
		
		@Override
		public void read(ExecutableStream s) throws Exception {
		    OffsetToData = s.readAddrInt();
		    Size = s.readAddrInt();
		    CodePage = s.readAddrInt();
		    Reserved = s.readAddrInt();
		}
		
		/**
		 * Return the data of this resource as a byte array
		 * @return the data of this resource
		 * @throws IOException something went wrong while parsing the entry
		 */
		public byte[] getData() throws IOException {
			byte[] data = new byte[getSize()];
			//???
			//why do I have to subtract the VIRTUAL ADDRESS of this offset?
			//and why do I only have to do this for the data entries data?!
			//Weird.
			int offset = getOffsetToData() - reader.offset2rva(reader.getOptionalHeader().getResourceOffset()).getAddr32() +reader.getOptionalHeader().getResourceOffset();
			for(int i=0;i<data.length;i++)
				data[i] = reader.getStream().getByte(offset+i);
			return data;
		}
		
		/**
		 * Return the RVA to to the resources data
		 * @return the RVA to the data
		 */
		public int getOffsetToData() {
			try {
				return reader.getStream().getInt(OffsetToData);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the RVA to the resources data
		 * @param offsetToData the new RVA to the data
		 */
		public void setOffsetToData(int offsetToData) {
			try {
				reader.getStream().setInt(OffsetToData, offsetToData);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the size of the resources data
		 * @return the size of the resource
		 */
		public int getSize() {
			try {
				return reader.getStream().getInt(Size);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the size of the resources data
		 * @param size the new size of the data
		 */
		public void setSize(int size) {
			try {
				reader.getStream().setInt(Size, size);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the Unicode codepage used for parsing Unicode strings of the resource if any
		 * @return the Unicode codepage
		 */
		public int getCodePage() {
			try {
				return reader.getStream().getInt(CodePage);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
		
		/**
		 * Set the Unicode codepage used for parsing Unicdoe strings of the resource if any
		 * @param codePage the new Unicode codepage
		 */
		public void setCodePage(int codePage) {
			try {
				reader.getStream().setInt(CodePage, codePage);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the value of the reserved field, should be 0
		 * @return the value of the reserved field
		 */
		public int getReserved() {
			try {
				return reader.getStream().getInt(Reserved);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the value of the reserved field, should be 0
		 * @param reserved the new value of the reserved field
		 */
		public void setReserved(int reserved) {
			try {
				reader.getStream().setInt(Reserved, reserved);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

	}
}
