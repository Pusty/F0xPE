F0xPE - PE/MZ Parser and Modification Library
=============================================

# What is this

F0xPE is a Windows Executable (PE format) parser and modification library written in Java.
It is meant to be used to extract information from headers and structures within the executables
and to modify them in an automated fashion. The library supports the 32bit and 64bit versions
of the format and abstracts them away unless needed otherwise. Creation of new executables from
scratch is also possible.

# Examples

The examples package contains example showcasing
- Printing out the Import and Resource Table (ExamplePrintTables.java)
- Adding a section and modifying the imports (ExampleImportEditing.java)
- Packing/Encrypting of an executable using an existing stub (ExamplePacker.java)

```java
    ExecutableReader reader = ExecutableReader.create(file);
    reader.getOptionalHeader().printImportTable();
```


# Still missing / TODO
- Only the Import Table, Resource Table and TLS Directory Entry are parsed and contain modification code
- Executable Creation from scratch is only barely implemented
- Modifying large import tables takes a lot of time (table moving algorithm is very slow)
