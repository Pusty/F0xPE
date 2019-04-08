package pusty.f0xpe.pe;

import java.io.IOException;
import java.util.ArrayList;

import pusty.f0xpe.ExecutableStream;
import pusty.f0xpe.ReadableObject;
import pusty.f0xpe.location.Address;
import pusty.f0xpe.pe.ExecutableReader;

/** 
 * A class representing the PE Import Table Structure 
 * <br>Reference: https://msdn.microsoft.com/en-us/library/ms809762.aspx
 */
public class DescriptorImport extends ReadableObject {

	/**
	 * The array containing all single import entries of this import table
	 */
	protected IMAGE_IMPORT_DESCRIPTOR[] importArray;
	
	
	/**
	 * Create a new Import Table Structure at the given index the reader is at
	 * @param reader the reader to parse the import table at
	 * @throws Exception something went wrong
	 */
	public DescriptorImport(ExecutableReader reader)
			throws Exception {
		super(reader);
	}
	

	@Override
	public void read(ExecutableStream s) throws Exception {
		ArrayList<IMAGE_IMPORT_DESCRIPTOR> imports = new ArrayList<IMAGE_IMPORT_DESCRIPTOR>();
		IMAGE_IMPORT_DESCRIPTOR tempDesc = new IMAGE_IMPORT_DESCRIPTOR(reader);
		while(!tempDesc.isEmpy()) { //While the entry isn't empty read new ones
			imports.add(tempDesc);
			tempDesc = new IMAGE_IMPORT_DESCRIPTOR(reader);
		}
		importArray = imports.toArray(new IMAGE_IMPORT_DESCRIPTOR[imports.size()]);
	
	}
	
	/**
	 * Return the imports of this Import Table
	 * @return the IMAGE_IMPORT_DESCRIPTOR entries of this table
	 */
	public IMAGE_IMPORT_DESCRIPTOR[] getImports() {
		return importArray;
	}
	
	/**
	 * A class representing the IMAGE_IMPORT_DESCRIPTOR structure (which again represents a DLL and its imports)
	 */
	public static class IMAGE_IMPORT_DESCRIPTOR extends ReadableObject {
		
		//UNION
		/** Originally used for holding characteristics of an import, no longer used for that */
		protected int Characteristics;
		/** RVA to an array of pointers to IMAGE_THUNK_DATA structures */
		protected int OriginalFirstThunk;
		//UNION END
	    
		/** The time this file was build */
		protected int TimeDateStamp;
		/** This field is related to import forwarding from one DLL to another, method of doing this is officially undocumented */
		protected int ForwarderChain;
		/** An RVA to a NULL-terminated ASCII String containing the name of this dynamic linked library */
		protected int Name;
		/** RVA to an array of pointers to IMAGE_THUNK_DATA structure containing the method of importing the actual functions */
		protected int FirstThunk;
	    
		/**
		 * Create a IMAGE_IMPORT_DESCRIPTOR structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_IMPORT_DESCRIPTOR(ExecutableReader reader)
				throws Exception {
			super(reader);
		}
		
		@Override
		public void read(ExecutableStream s) throws Exception {
			Characteristics = s.readAddrInt();
			s.setIndex(s.getIndex()-4);
			OriginalFirstThunk = s.readAddrInt(); //RVA to list of pointers (RVAs) to IMAGE_IMPORT_BY_NAME
	
		    TimeDateStamp = s.readAddrInt(); //Date when file was build
		    ForwarderChain = s.readAddrInt(); //Index within Thunks to forward to another DLL
		    Name = s.readAddrInt(); //RVA to Null-Terminated ASCII String
		    FirstThunk = s.readAddrInt(); //RVA to IMAGE_THUNK_DATA
		}
		
		/** 
		 * The name of this DLL as a String
		 * @return the name of the imported DLL represented by this structure
		 * @throws IOException something went wrong trying to read the name
		 */
		public String getDLLName() throws IOException {
			return reader.getStream().getString(reader.rva2offset(new Address(this.getName())));
		}
		
		/**
		 * Parse the OriginalFirstThunk tables imports into an array
		 * @return the IMAGE_THUNK_DATA array of the OriginalFirstThunk table
		 * @throws Exception something went wrong parsing the table
		 */
		public IMAGE_THUNK_DATA[] parseHintNameTable() throws Exception {
			return parseTableAt(this.getOriginalFirstThunkOffset());
		}
		
		/**
		 * Parse the FirstThunk tables imports into an array
		 * @return the IMAGE_THUNK_DATA array of the FirstThunk table
		 * @throws Exception something went wrong parsing the table
		 */
		public IMAGE_THUNK_DATA[] parseImportTable() throws Exception {
			return parseTableAt(this.getFirstThunkOffset());
		}
		
		/**
		 * Parse an array of pointers to IMAGE_THUNK_DATA structures
		 * @param firstThunkOffset the offset to the import table
		 * @return the IMAGE_THUNK_DATA array of the table
		 * @throws Exception something went wrong parsing the table
		 */
		public IMAGE_THUNK_DATA[] parseTableAt(int firstThunkOffset) throws Exception {
			ArrayList<IMAGE_THUNK_DATA> table = new ArrayList<IMAGE_THUNK_DATA>();
			int temp = reader.getStream().getIndex();
			reader.getStream().setIndex(firstThunkOffset); //RVA to RVA Table
			IMAGE_THUNK_DATA data;
			while(true) {
				data = IMAGE_THUNK_DATA.readImageThunk(reader);
				if(data.isNull()) break;
				table.add(data);
			}
			reader.getStream().setIndex(temp);
			return table.toArray(new IMAGE_THUNK_DATA[table.size()]);
		}
		
		/**
		 * Return the OrginalFirstThunk as an offset
		 * @return the OrginalFirstThunk as an offset instead of an RVA
		 */
		public int getOriginalFirstThunkOffset() {
			return reader.rva2offset(new Address(getOriginalFirstThunk()));
		}
		
		/**
		 * Return the FirstThunk as an offset
		 * @return the FirstThunk as an offset instead of an RVA
		 */
		public int getFirstThunkOffset() {
			return reader.rva2offset(new Address(getFirstThunk()));
		}
	
		/**
		 * Return the content of the Characteristics field which was originally used for holding characteristics of an import
		 * <br>NOTE: This is in a union with OriginalFirstThunk
		 * @return the characteristics of this import
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
		 * Set the characteristics of this import if actually used for that
		 * <br>NOTE: This is in a union with OriginalFirstThunk
		 * @param characteristics the new characteristics of this import
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
		 * Return an RVA to an array of pointers to IMAGE_THUNK_DATA structures
		 * <br>NOTE: This is in a union with Characteristics
		 * @return a pointer to the the original first thunk
		 */
		public int getOriginalFirstThunk() {
			try {
				return reader.getStream().getInt(OriginalFirstThunk);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
	
		/**
		 * Set the RVA to an array of pointers to IMAGE_THUNK_DATA structures
		 * <br>NOTE: This is in a union with Characteristics
		 * @param characteristics the new pointer to the the original first thunk
		 */
		public void setOriginalFirstThunk(int originalFirstThunk) {
			try {
				reader.getStream().setInt(OriginalFirstThunk, originalFirstThunk);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}
	
		/**
		 * Return the time this file was build 
		 * @return the time stamp of this import
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
		 * Set the time this file was build
		 * @param timeDateStamp the new time stamp of this import
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
		 * Return the content of the ForwarderChain field which is related to import forwarding from one DLL to another, method of doing this is officially undocumented
		 * @return the ForwarderChain fields value
		 */
		public int getForwarderChain() {
			try {
				return reader.getStream().getInt(ForwarderChain);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
	
		/**
		 * Set the content of the ForwarderChain field of this import
		 * @param forwarderChain the new ForwarderChain value
		 */
		public void setForwarderChain(int forwarderChain) {
			try {
				reader.getStream().setInt(ForwarderChain, forwarderChain);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		/**
		 * Return the RVA to a NULL-terminated ASCII String containing the name of this DLL
		 * @return the RVA to the name
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
		 * Set the RVA to a NULL-terminated ASCII String containing the name of this DLL
		 * @param name the new RVA to the name
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
		 * Return the FirstThunk fields value which is an RVA to an array of pointers to IMAGE_THUNK_DATA structures containing the method of importing the actual functions
		 * @return the RVA to an array of pointers
		 */
		public int getFirstThunk() {
			try {
				return reader.getStream().getInt(FirstThunk);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
	
		/**
		 * Set the FirstThunk RVA to an array of pointers to IMAGE_THUNK_DATA structures
		 * @param firstThunk the new RVA
		 */
		public void setFirstThunk(int firstThunk) {
			try {
				reader.getStream().setInt(FirstThunk, firstThunk);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}
	}
	
	/**
	 * A class representing the IMAGE_IMPORT_BY_NAME structure (which itself represents an import by the name of a function)
	 */
	public static class IMAGE_IMPORT_BY_NAME extends ReadableObject{
		
		/** This field indicates the best guess at which ordinal the import may lay, doesn't have to be correct */
		protected int Hint;
		/** Offset to the ASCIIZ String with the name of the import */
		protected int Name;
		/** The name of the import as a Java String */
		protected String NameStr;

	    
		/**
		 * Create a IMAGE_IMPORT_BY_NAME structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_IMPORT_BY_NAME(ExecutableReader reader)
				throws Exception {
			super(reader);
		}

		@Override
		public void read(ExecutableStream s) throws Exception {
			Hint = s.readAddrShort();
			Name = s.getIndex();
			NameStr = s.getString(Name);
			s.setIndex(Name+NameStr.length()+1);
		}
		
		/**
		 * Return the name of the import as a String
		 * @return the name of the imported function
		 */
		public String getName() {
			return NameStr;
		}

		/**
		 * Set the name of this import by a given string
		 * <br>NOTE: Watch out to not write a longer import than the previous one or you will overwrite possibly important data
		 * @param str the new name of the function of this import
		 */
		public void setString(String str) {
			try {
				//Empty old string
				if(getName() != null)
					for(int i=0;i<getName().length()+1;i++)
						reader.getStream().setByte(Name+i, (byte)0);
				//Write in the new string
				for(int i=0;i<str.length();i++)
						reader.getStream().setByte(Name+i, (byte)(str.charAt(i)&0xFF));
				//Zero terminate the new string
				reader.getStream().setByte(Name+str.length(), (byte)0);
				NameStr = reader.getStream().getString(Name);
				reader.getStream().setIndex(Name+NameStr.length()+1);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		/**
		 * Get the Hint to the ordinal of this import
		 * @return the content of the Hint field
		 */
		public short getHint() {
			try {
				return reader.getStream().getShort(Hint);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}

		/**
		 * Set the Hint to the ordinal of this import
		 * @param hint the new best guess of the position of this import
		 */
		public void setHint(short hint) {
			try {
				reader.getStream().setShort(Hint, hint);
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}

		
		
		
	}
	
	
	/**
	 * A class representing the generic IMAGE_THUNK_DATA structure
	 * <br>NOTE: 32bit and 64bit have different specific implementations and sizes
	 */
	public static abstract class IMAGE_THUNK_DATA extends ReadableObject {
		//UNION
		/** Related to importing by Forwarding, undocumented */
	    public int ForwarderString;
	    /** Address to a function */
	    public int Function;
	    /** Ordinal of the function to import */
	    public int Ordinal;
	    /** Address of the  IMAGE_IMPORT_BY_NAME structure of this import */
	    public int AddressOfData;
	    //UNION END
	    
		/**
		 * Create a IMAGE_THUNK_DATA structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_THUNK_DATA(ExecutableReader reader)
				throws Exception {
			super(reader);
		}
		
		/**
		 * Return whether this import is done with an ordinal value
		 * @return if this is an import by ordinal
		 */
		public abstract boolean isOrdinal();
		
		/**
		 * Return the ordinal value of this import if it's an import by ordinal, -1 if not
		 * @return the ordinal value of this import
		 */
		public abstract int getOrdinal();
		
		/**
		 * Return the offset to the IMAGE_IMPORT_BY_NAME structure , -1 if import by ordinal
		 * @return the offset to an IMAGE_IMPORT_BY_NAME structure or -1
		 */
		public abstract int getNameOffset();
		
		/**
		 * The IMAGE_IMPORT_BY_NAME of this IMAGE_THUNK_DATA, null if an import by ordinal
		 * @return the IMAGE_IMPORT_BY_NAME of this import, null if import by ordinal
		 * @throws Exception something went wrong while parsing
		 */
		public abstract IMAGE_IMPORT_BY_NAME getImportByName() throws Exception;
		
		/**
		 * The name of the import by name, null if an import by ordinal
		 * @return the name of the function to import, null if an import by ordinal value
		 */
		public abstract String getName();	
		
		/**
		 * Set the internal value to an ordinal with the given index, does also add the necessary indicators to mark this as an ordinal import
		 * @param i the new ordinal value of this import
		 */
		public abstract void setOrdinal(int i);
		
		/**
		 * Set the position of the IMAGE_IMPORT_BY_NAME by supplying an offset
		 * @param o the offset to the new IMAGE_IMPORT_BY_NAME structure of this import
		 */
		public abstract void setNameOffset(int o);
		
		/**
		 * Set the position of the IMAGE_IMPORT_BY_NAME by supplying an RVA
		 * @param o the RVA to the new IMAGE_IMPORT_BY_NAME structure of this import
		 */
		public abstract void setNameRVA(int o);		
		
		/**
		 * Return the content of the internal value
		 * @return the content of this IMAGE_THUNK_DATA structure
		 */
		public abstract int getNameRVA();
		
		/**
		 * Return whether the content of this null
		 * @return if this thunk contains a zero value
		 */
		public boolean isNull() {
			if(isOrdinal()) return false;
			return (getNameOffset()==0);
		}
		
		/**
		 * Read a architecture specific IMAGE_THUNK_DATA for a given reader
		 * @param reader the reader to read from and which decides the format of the read thunks
		 * @return the resulting read thunk
		 */
		public static IMAGE_THUNK_DATA readImageThunk(ExecutableReader reader) {
			try {
				if(reader.is32bit()) {
					return new IMAGE_THUNK_DATA32(reader);
				}else {
					return new IMAGE_THUNK_DATA64(reader);
				}
			}catch(Exception e) {
				e.printStackTrace();
			}
			return null;
		}
		
	}
	
	/**
	 * A class for representing the 32bit implementation of the IMAGE_THUNK_DATA structure
	 */
	public static class IMAGE_THUNK_DATA32 extends IMAGE_THUNK_DATA{
		
		/** A bit mask for determining whether an import is an import by ordinal value */
		public static int IMAGE_ORDINAL_FLAG32 = 0x80000000;
		
		/**
		 * Create a IMAGE_THUNK_DATA32 structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_THUNK_DATA32(ExecutableReader reader)
				throws Exception {
			super(reader);
		}
		
		@Override
		public void read(ExecutableStream s) throws Exception {
	        ForwarderString = s.readAddrInt();
	        s.setIndex(s.getIndex()-4);
	        Function = s.readAddrInt();
	        s.setIndex(s.getIndex()-4);
	        Ordinal = s.readAddrInt();
	        s.setIndex(s.getIndex()-4);
	        AddressOfData = s.readAddrInt();
	        //If read value &IMAGE_ORDINAL_FLAG == 1 => ordinal else rva to import by name
		}
		
		/**
		 * Architecture depending read from a 32bit thunk
		 * @return the raw value of this thunk
		 */
		public int getGenericValue() {
			try {
				return reader.getStream().getInt(Ordinal);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
		
		/**
		 * Architecture depending write to a 32bit thunk
		 * @param l the raw new value of this thunk
		 */
		public void setGenericValue(int l) {
			try {
				reader.getStream().setInt(Ordinal, l);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		@Override
		public boolean isOrdinal() {
			try {
				return (reader.getStream().getInt(Ordinal)&IMAGE_ORDINAL_FLAG32)!=0;
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		
		@Override
		public int getOrdinal() {
			if(!isOrdinal()) return -1;
			try {
				return (int) (reader.getStream().getInt(Ordinal)&(~IMAGE_ORDINAL_FLAG32));
			} catch (IOException e) {
				e.printStackTrace();
				return -1;
			}
		}
		
		@Override
		public int getNameOffset() {
			if(isOrdinal()) return -1;
			try {
				return reader.rva2offset(new Address(reader.getStream().getInt(ForwarderString)));
			} catch (IOException e) {
				e.printStackTrace();
				return -1;
			}
		}
		
		@Override
		public IMAGE_IMPORT_BY_NAME getImportByName() throws Exception {
			if(isOrdinal()) return null;
			int temp = reader.getStream().getIndex();
			reader.getStream().setIndex(getNameOffset());
			IMAGE_IMPORT_BY_NAME iibn = new IMAGE_IMPORT_BY_NAME(reader);
			reader.getStream().setIndex(temp);
			return iibn;
		}
		
		@Override
		public String getName() {
			if(isOrdinal()) return null;
			try {
				return getImportByName().getName();
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		
		@Override
		public void setOrdinal(int i) {
			try {
				reader.getStream().setInt(Ordinal, i|IMAGE_ORDINAL_FLAG32);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		@Override
		public void setNameOffset(int o) {
			try {
				reader.getStream().setInt(ForwarderString, reader.offset2rva(o).getAddr32());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}	
		
		
		@Override
		public void setNameRVA(int o) {
			try {
				reader.getStream().setInt(ForwarderString, o);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		@Override
		public int getNameRVA() {
			try {
				return reader.getStream().getInt(ForwarderString);
			} catch (IOException e) {
				e.printStackTrace();
				return -1;
			}
		}
		
	}
	
	/**
	 * A class for representing the 64bit implementation of the IMAGE_THUNK_DATA structure
	 */
	public static class IMAGE_THUNK_DATA64 extends IMAGE_THUNK_DATA{
		
		/** A bit mask for determining whether an import is an import by ordinal value */
		public static long IMAGE_ORDINAL_FLAG64 = 0x8000000000000000L;
		
		/**
		 * Create a IMAGE_THUNK_DATA64 structure at the given readers index
		 * @param reader the reader to create this structure at
		 * @throws Exception something went wrong
		 */
		public IMAGE_THUNK_DATA64(ExecutableReader reader)
				throws Exception {
			super(reader);
		}

		@Override
		public void read(ExecutableStream s) throws Exception {
	        ForwarderString = s.readAddrLong();
	        s.setIndex(s.getIndex()-8);
	        Function = s.readAddrLong();
	        s.setIndex(s.getIndex()-8);
	        Ordinal = s.readAddrLong();
	        s.setIndex(s.getIndex()-8);
	        AddressOfData = s.readAddrLong();
	       //If read value &IMAGE_ORDINAL_FLAG == 1 => ordinal else rva to import by name
		}
		
		/**
		 * Architecture depending read from a 64bit thunk
		 * @return the raw value of this thunk
		 */
		public long getGenericValue() {
			try {
				return reader.getStream().getLong(Ordinal);
			} catch (IOException e) {
				e.printStackTrace();
				return 0;
			}
		}
		
		/**
		 * Architecture depending write to a 64bit thunk
		 * @param l the raw new value of this thunk
		 */
		public void setGenericValue(long l) {
			try {
				reader.getStream().setLong(Ordinal, l);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		@Override
		public boolean isOrdinal() {
			try {
				return (reader.getStream().getLong(Ordinal)&IMAGE_ORDINAL_FLAG64)!=0;
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		
		@Override
		public int getOrdinal() {
			if(!isOrdinal()) return -1;
			try {
				return (int) (reader.getStream().getLong(Ordinal)&(~IMAGE_ORDINAL_FLAG64));
			} catch (IOException e) {
				e.printStackTrace();
				return -1;
			}
		}
		
		@Override
		public int getNameOffset() {
			if(isOrdinal()) return -1;
			try {
				return reader.rva2offset(new Address(reader.getStream().getLong(ForwarderString)));
			} catch (IOException e) {
				e.printStackTrace();
				return -1;
			}
		}
		
		@Override
		public IMAGE_IMPORT_BY_NAME getImportByName() throws Exception {
			if(isOrdinal()) return null;
			int temp = reader.getStream().getIndex();
			reader.getStream().setIndex(getNameOffset());
			IMAGE_IMPORT_BY_NAME iibn = new IMAGE_IMPORT_BY_NAME(reader);
			reader.getStream().setIndex(temp);
			return iibn;
		}
		
		@Override
		public String getName() {
			if(isOrdinal()) return null;
			try {
				return getImportByName().getName();
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		
		@Override
		public void setOrdinal(int i) {
			try {
				reader.getStream().setLong(Ordinal, i|IMAGE_ORDINAL_FLAG64);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		@Override
		public void setNameOffset(int o) {
			try {
				reader.getStream().setLong(ForwarderString, reader.offset2rva(o).getAddr64());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
			
		@Override
		public void setNameRVA(int o) {
			try {
				reader.getStream().setLong(ForwarderString, o);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		@Override
		public int getNameRVA() {
			try {
				return (int)reader.getStream().getLong(ForwarderString);
			} catch (IOException e) {
				e.printStackTrace();
				return -1;
			}
		}
		
	}	
}
