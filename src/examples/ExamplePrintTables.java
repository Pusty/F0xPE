package examples;

import java.io.File;

import pusty.f0xpe.pe.ExecutableReader;

//Testing Reading of Import Table/Resource Table
public class ExamplePrintTables {
	
	
	public static void main(String[] args) throws Exception {
		File file = new File(args[0]);
		ExecutableReader reader = ExecutableReader.create(file);
		reader.getOptionalHeader().printImportTable();
		reader.getOptionalHeader().printResourceTable();
	}
	
	
}
