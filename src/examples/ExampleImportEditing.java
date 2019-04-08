package examples;

import java.io.File;

import pusty.f0xpe.payload.ModifyPE;
import pusty.f0xpe.payload.ModifyPE.EditableImportTable;
import pusty.f0xpe.pe.ExecutableReader;
import pusty.f0xpe.pe.IMAGE_SECTION_HEADER;

/**
 * An Example demonstrating how to edit imports of an executable
 */
public class ExampleImportEditing {
	
	public static void main(String[] args) throws Exception {
		File file = new File(args[0]);
		ExecutableReader reader = ExecutableReader.create(file);
		//inject a new section
		int sec = ModifyPE.injectSection(reader, "PING", 0x2024, IMAGE_SECTION_HEADER.IMAGE_SCN_MEM_READ  | IMAGE_SECTION_HEADER.IMAGE_SCN_CNT_INITIALIZED_DATA );
		//modify one import of the import table and put it into the next section
		ModifyPE.replaceImport(reader, "kernel32.dll", "IsDebuggerPresent", "ExitProcess", reader.getSectionHeader()[sec].getPointerToRawData());
		//parse the import table from the reader
		EditableImportTable table = EditableImportTable.fromReader(reader);
		//write the table to the new section
		table.writeTable(reader, reader.getSectionHeader()[sec].getPointerToRawData());
		reader.save(new File("output.exe"));
		
	}

}
