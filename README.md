# Static PE Import Address Table (IAT) Parser
#### Description: A native Windows PE static analysis utility written in pure C that maps portable executable binaries on disk to parse and enumerate imported DLLs, function names, import hints, and ordinals. Building directly upon previous PE structural header parsers, this tool resolves Relative Virtual Addresses (RVAs) to physical file offsets using section headers to traverse import descriptors and thunk data directories.
#### Date: 15 October 2026

## Features:
- **Robust Argument & Path Validation:** Ensures precise command-line argument counts and protects against empty file path inputs.
- **Memory-Mapped File I/O:** Utilizes Win32 file mapping APIs (CreateFileMappingA, MapViewOfFile) for efficient, read-only binary inspection.
- **Comprehensive Header Validation:** Validates DOS magic signatures, minimum/alignment bounds for e_lfanew, and prevents integer overflows.
- **Dual-Architecture Target Support:** Automatically detects and branches for both PE32 (32-bit) and PE32+ (64-bit) binary formats.
- **Structured Characteristics & Subsystem Parsing:** Uses mapped flag lookup tables to cleanly output NT Header file characteristics and subsystem types.
- **Import Directory Resolution:** Navigates Optional Header Data Directories to locate the IMAGE_DIRECTORY_ENTRY_IMPORT table.
- **Dual-Table Thunk Traversal:** Parses both the Import Name Table (OriginalFirstThunk) and the Import Address Table (FirstThunk).
- **Ordinal vs. Name Decoding:** Inspects most significant bits (MSB) to correctly distinguish between ordinal imports and named imports with hint indices.
- **Accurate RVA-to-File-Offset Conversion:** Maps virtual addresses back to physical file offsets by walking the section header table.

## Compilation & Usage:
**Prerequisites:**  
Any C standard compliant compiler such as gcc, clang, ...

**Build Instructions Example Using GCC:**
gcc -Wall -Wextra -O3 main.c -o IATParser

*IATParser is the name of the program, you can name it anything you want

**Execution Examples:**  
- **General Syntax:** .\IATParser.exe \<path_to_target\>
- **Example:** .\IATParser.exe IATParser.exe

## Sample Output:
```
==============================================================================================
                                        PE IAT Parser                                        
==============================================================================================
File Path: IATParser.exe
File Size: 100.05 KB
-------------------------------------------------

DOS Header:
- DOS Signature: 0x5A4D (Valid)
- e_lfanew: 0x80 (Valid)
-------------------------------------------------

NT Headers:
- Signature: 0x4550 (Valid)
- Target Architecture: AMD64
- Compiled Time: 1792049094 (Thu Oct 15 07:24:54 2026 UTC)
- Number of Sections: 18
- Characteristics: 0x26 (EXECUTABLE_IMAGE, LINE_NUMS_STRIPPED, LARGE_ADDRESS_AWARE)
-------------------------------------------------

Optional Headers:
- Target Architecture: PE32+ (64-bit)
- Entry Point: 0x0000105F
- Image Base: 0x140000000
- Section Alignment: 4096 Bytes
- File Alignment: 512 Bytes
- Subsystem: Windows CUI (Console)
- Size of Image: 120.00 KB
- Size of Headers: 1536 Bytes
-------------------------------------------------

Import Address Table:
  DLL #1: KERNEL32.dll
    [0000] ByName -> CloseHandle (Hint: 151)
    [0001] ByName -> CreateFileA (Hint: 215)
    [0002] ByName -> CreateFileMappingA (Hint: 216)
    [0003] ByName -> DeleteCriticalSection (Hint: 295)
    [0004] ByName -> EnterCriticalSection (Hint: 333)
    [0005] ByName -> FreeLibrary (Hint: 458)
    [0006] ByName -> GetCPInfo (Hint: 481)
    [0007] ByName -> GetFileSizeEx (Hint: 627)
    [0008] ByName -> GetLastError (Hint: 648)
    [0009] ByName -> GetModuleHandleA (Hint: 670)
    [0010] ByName -> GetProcAddress (Hint: 730)
    [0011] ByName -> InitializeCriticalSection (Hint: 918)
    [0012] ByName -> LeaveCriticalSection (Hint: 1012)
    [0013] ByName -> LoadLibraryA (Hint: 1016)
    [0014] ByName -> MapViewOfFile (Hint: 1047)
    [0015] ByName -> MultiByteToWideChar (Hint: 1064)
    [0016] ByName -> SetUnhandledExceptionFilter (Hint: 1433)
    [0017] ByName -> Sleep (Hint: 1449)
    [0018] ByName -> TlsGetValue (Hint: 1485)
    [0019] ByName -> VirtualProtect (Hint: 1533)
    [0020] ByName -> VirtualQuery (Hint: 1535)
    [0021] ByName -> WideCharToMultiByte (Hint: 1588)

  DLL #2: msvcrt.dll
    [0000] ByName -> __C_specific_handler (Hint: 89)
    [0001] ByName -> ___lc_codepage_func (Hint: 109)
    [0002] ByName -> ___mb_cur_max_func (Hint: 112)
    [0003] ByName -> __getmainargs (Hint: 127)
    [0004] ByName -> __initenv (Hint: 128)
    [0005] ByName -> __iob_func (Hint: 130)
    [0006] ByName -> __set_app_type (Hint: 146)
    [0007] ByName -> __setusermatherr (Hint: 148)
    [0008] ByName -> _amsg_exit (Hint: 181)
    [0009] ByName -> _cexit (Hint: 202)
    [0010] ByName -> _commode (Hint: 222)
    [0011] ByName -> _errno (Hint: 272)
    [0012] ByName -> _fmode (Hint: 324)
    [0013] ByName -> _gmtime64 (Hint: 398)
    [0014] ByName -> _initterm (Hint: 410)
    [0015] ByName -> _lock (Hint: 518)
    [0016] ByName -> _unlock (Hint: 911)
    [0017] ByName -> atexit (Hint: 1125)
    [0018] ByName -> abort (Hint: 1138)
    [0019] ByName -> calloc (Hint: 1156)
    [0020] ByName -> exit (Hint: 1170)
    [0021] ByName -> fflush (Hint: 1177)
    [0022] ByName -> fprintf (Hint: 1192)
    [0023] ByName -> fputc (Hint: 1194)
    [0024] ByName -> free (Hint: 1198)
    [0025] ByName -> localeconv (Hint: 1254)
    [0026] ByName -> malloc (Hint: 1261)
    [0027] ByName -> memcpy (Hint: 1270)
    [0028] ByName -> puts (Hint: 1284)
    [0029] ByName -> setvbuf (Hint: 1302)
    [0030] ByName -> signal (Hint: 1303)
    [0031] ByName -> strerror (Hint: 1323)
    [0032] ByName -> strftime (Hint: 1324)
    [0033] ByName -> strlen (Hint: 1325)
    [0034] ByName -> strncmp (Hint: 1328)
    [0035] ByName -> vfprintf (Hint: 1362)
    [0036] ByName -> wcslen (Hint: 1386)
```

## Engineering Journal and Implementation Process:
When researching this project, I noticed that a huge chunk of it shares about 80% of its implementation with Project 4. You need to open a PE file, map it, and read through the DOS and NT Headers. The key difference is that instead of continuing to the Section Headers to list them out directly, we pivot into the IMAGE_DATA_DIRECTORY structure inside the Optional Header to find our imports.

Here is how I built the project step by step:

### Step 1: Argument & Path Validation
First, I made sure the argument count was strictly handled:
```c
if (argc < 2) {
    printf("Please provide the path of the PE File!\n");
    return -1;
}
if (argc > 2) {
    printf("Too many arguments! The program expects a single path to a PE file!\n");
    return -1;
}
```

### Step 2: File Opening & Memory Mapping
Next, I opened the file using CreateFileA, fetched its size with GetFileSizeEx, and mapped its content into memory using CreateFileMappingA and MapViewOfFile:
```c
HANDLE fileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

// ...

HANDLE fileMappingHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID mapViewPointer = MapViewOfFile(fileMappingHandle, FILE_MAP_READ, 0, 0, 0);
BYTE* basePointer = (BYTE*)mapViewPointer;
```

### Step 3: DOS Header & e_lfanew Validation
I grabbed the DOS Header pointer and validated both the magic signature (0x5A4D) and e_lfanew pointer boundaries to prevent overflows or reading out of bounds:
```c
PIMAGE_DOS_HEADER dosHeaderPointer = (PIMAGE_DOS_HEADER)basePointer;
printf("- DOS Signature: ");
if (dosHeaderPointer->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("0x%X (Invalid)\n", dosHeaderPointer->e_magic);
    
    // exiting
}
printf("0x%X (Valid)\n", dosHeaderPointer->e_magic);

printf("- e_lfanew: ");
if (dosHeaderPointer->e_lfanew < 64) {
    printf("0x%lX (Invalid - Smaller than 64)\n", dosHeaderPointer->e_lfanew);

    // exiting
} else if ((dosHeaderPointer->e_lfanew % 4) != 0) {
    printf("0x%lX (Invalid - Not aligned to 4)\n", dosHeaderPointer->e_lfanew);

    // exiting
} else if ((dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > UINT32_MAX) {
    printf("0x%lX (Invalid - Overflow)\n", dosHeaderPointer->e_lfanew);

    // exiting
} else if ((dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > (unsigned long long)fileSize.QuadPart) {
    printf("0x%lX (Invalid - Larger than the file itself)\n", dosHeaderPointer->e_lfanew);

    // exiting
}
printf("0x%lX (Valid)\n", dosHeaderPointer->e_lfanew);
```

### Step 4: NT Headers & Characteristics Mapping
Moving to the NT Headers, I checked the signature (0x4550), architecture, compilation timestamp, and characteristics. For characteristics, I refactored the output logic into a cleaner helper function (PrintFileCharacteristics) using a FlagMap struct:
```c
struct FlagMap {
    WORD flag;
    const char* name;
};
```

### Step 5: Optional Headers & Unified Subsystem Resolution
I parsed the Optional Header depending on whether it was PE32 or PE32+, extracting entry points, image bases, and formatting sizes cleanly into KB and bytes. I also consolidated subsystem printing into a single clean PrintSubSystem function.

### Step 6: Unlocking the Import Data Directory
This is where the new logic started. I accessed the DataDirectory array inside the Optional Header and targeted index IMAGE_DIRECTORY_ENTRY_IMPORT (index 1). The VirtualAddress at this index points to an array of IMAGE_IMPORT_DESCRIPTOR structures representing all imported DLLs.

### Step 7: Traversing INTs, IATs, and Resolving Ordinals vs. Names
Each import descriptor contains two key addresses:
- **OriginalFirstThunk (INT):** The Import Name Table. A static read-only array of pointers (IMAGE_THUNK_DATA) pointing to function names.
- **FirstThunk (IAT):** The Import Address Table. On disk, it mirrors the INT.

Each element in these tables is an IMAGE_THUNK_DATA structure. To figure out if a function is imported by ordinal or name, I checked the most significant bit (MSB) against the ordinal flag:
- If set, it's an ordinal import; I masked out the flag to extract the ordinal number from the lower 16 bits.
- If not set, the value is an RVA pointing to an IMAGE_IMPORT_BY_NAME structure containing the function name hint and string.

### Step 8: RVA-to-File-Offset Section Mapping
Because this is an on-disk parser, I had to write an RvaToFileOffset function to iterate through the Section Headers, test which section contains our target RVA, and calculate the exact file offset (PointerToRawData + (rva - VirtualAddress)). Once resolved, reading the null-terminated function name strings was straightforward.

## References:
- [CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
- [GetFileSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesizeex)
- [LARGE_INTEGER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-large_integer-r1)
- [CreateFileMappingA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
- [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
- [IMAGE_NT_HEADERS32](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)
- [Machine Types](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types)
- [IMAGE_OPTIONAL_HEADERS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)