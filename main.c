#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

struct FlagMap {
    WORD flag;
    const char* name;
};

const struct FlagMap FileCharacteristicsTable[] = {
    { IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED" },
    { IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE" },
    { IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED" },
    { IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED" },
    { IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM" },
    { IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE" },
    { IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO" },
    { IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE" },
    { IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED" },
    { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP" },
    { IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP" },
    { IMAGE_FILE_SYSTEM, "SYSTEM" },
    { IMAGE_FILE_DLL, "DLL" },
    { IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY" },
    { IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI" }
};

bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime);
void PrintFileCharacteristics(WORD fileCharacteristics, int characteristicsTableSize);
void PrintSubSystem(WORD subSystem);
DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER sectionHeaders, WORD numberOfSections, DWORD rva);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Please provide the path of the PE File!\n");

        return -1;
    }

    if (argc > 2) {
        printf("Too many arguments! The program expects a single path to a PE file!\n");

        return -1;
    }

    if (strcmp(argv[1], "") == 0) {
        printf("The Path to the PE file should not be empty!\n");

        return -1;
    }

    printf("\n==============================================================================================\n");
    printf("                                        PE IAT Parser                                        \n");
    printf("==============================================================================================\n");

    HANDLE fileHandle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fileHandle == INVALID_HANDLE_VALUE) {
        printf("Couldn't open the PE File! Error Code: %lu\n", GetLastError());

        return -1;
    }

    printf("File Path: %s\n", argv[1]);

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(fileHandle, &fileSize)) {
        printf("Couldn't get the File Size! Error Code: %lu\n", GetLastError());

        CloseHandle(fileHandle);

        return -1;
    }

    printf("File Size: %.2lf KB\n", ((double)fileSize.QuadPart / 1024));
    printf("-------------------------------------------------\n");

    HANDLE fileMappingHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);

    if (fileMappingHandle == NULL) {
        printf("Couldn't create a file map! Error Code: %lu\n", GetLastError());

        CloseHandle(fileHandle);

        return -1;
    }

    LPVOID mapViewPointer = MapViewOfFile(fileMappingHandle, FILE_MAP_READ, 0, 0, 0);

    if (mapViewPointer == NULL) {
        printf("Couldn't map the file! Error Code: %lu\n", GetLastError());

        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    }

    BYTE* basePointer = (BYTE*)mapViewPointer;

    printf("\nDOS Header:\n");
    PIMAGE_DOS_HEADER dosHeaderPointer = (PIMAGE_DOS_HEADER)basePointer;

    printf("- DOS Signature: ");
    if (dosHeaderPointer->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("0x%X (Invalid)\n", dosHeaderPointer->e_magic);
        
        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    }
    printf("0x%X (Valid)\n", dosHeaderPointer->e_magic);

    printf("- e_lfanew: ");
    if (dosHeaderPointer->e_lfanew < 64) {
        printf("0x%lX (Invalid - Smaller than 64)\n", dosHeaderPointer->e_lfanew);

        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    } else if ((dosHeaderPointer->e_lfanew % 4) != 0) {
        printf("0x%lX (Invalid - Not aligned to 4)\n", dosHeaderPointer->e_lfanew);

        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    } else if ((dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > UINT32_MAX) {
        printf("0x%lX (Invalid - Overflow)\n", dosHeaderPointer->e_lfanew);

        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    } else if ((dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) > (unsigned long long)fileSize.QuadPart) {
        printf("0x%lX (Invalid - Larger than the file itself)\n", dosHeaderPointer->e_lfanew);

        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    }
    printf("0x%lX (Valid)\n", dosHeaderPointer->e_lfanew);
    printf("-------------------------------------------------\n");

    printf("\nNT Headers:\n");
    PIMAGE_NT_HEADERS32 ntHeadersPointer = (PIMAGE_NT_HEADERS32)(basePointer + dosHeaderPointer->e_lfanew);

    printf("- Signature: ");
    if (ntHeadersPointer->Signature != 0x4550) {
        printf("0x%lX (Invalid)\n", ntHeadersPointer->Signature);

        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    }
    printf("0x%lX (Valid)\n", ntHeadersPointer->Signature);

    printf("- Target Architecture: ");
    if (ntHeadersPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        printf("I386\n");
    } else if (ntHeadersPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        printf("AMD64\n");
    } else if (ntHeadersPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64) {
        printf("ARM64\n");
    } else {
        printf("Unknown\n");
    }

    char formattedTimeStamp[64];
    bool formattingResult = FormatTime(formattedTimeStamp, sizeof(formattedTimeStamp), ntHeadersPointer->FileHeader.TimeDateStamp);

    printf("- Compiled Time: ");
    if (!formattingResult) {
        printf("%ld\n", ntHeadersPointer->FileHeader.TimeDateStamp);
    }
    printf("%ld (%s)\n", ntHeadersPointer->FileHeader.TimeDateStamp, formattedTimeStamp);

    WORD numberOfSections = ntHeadersPointer->FileHeader.NumberOfSections;
    printf("- Number of Sections: %d\n", numberOfSections);
    
    printf("- Characteristics: ");
    int characteristicsTableSize = 15;
    PrintFileCharacteristics(ntHeadersPointer->FileHeader.Characteristics, characteristicsTableSize);
    printf("-------------------------------------------------\n");

    BOOL is64 = FALSE;
    IMAGE_DATA_DIRECTORY importDirectory;
    printf("\nOptional Headers:\n");
    if (ntHeadersPointer->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("- Target Architecture: PE32 (32-bit)\n");
        printf("- Entry Point: 0x%08lX\n", ntHeadersPointer->OptionalHeader.AddressOfEntryPoint);
        printf("- Image Base: 0x%lX\n", ntHeadersPointer->OptionalHeader.ImageBase);
        printf("- Section Alignment: %ld Bytes\n", ntHeadersPointer->OptionalHeader.SectionAlignment);
        printf("- File Alignment: %ld Bytes\n", ntHeadersPointer->OptionalHeader.FileAlignment);
        printf("- Subsystem: ");
        PrintSubSystem(ntHeadersPointer->OptionalHeader.Subsystem);
        printf("- Size of Image: %.2lf KB\n", (double)ntHeadersPointer->OptionalHeader.SizeOfImage / 1024);
        printf("- Size of Headers: %ld Bytes\n", ntHeadersPointer->OptionalHeader.SizeOfHeaders);
    
        is64 = FALSE;
        importDirectory = ntHeadersPointer->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else if (ntHeadersPointer->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("- Target Architecture: PE32+ (64-bit)\n");
        
        PIMAGE_NT_HEADERS64 ntHeaders64Pointer = (PIMAGE_NT_HEADERS64)ntHeadersPointer;
        printf("- Entry Point: 0x%08lX\n", ntHeaders64Pointer->OptionalHeader.AddressOfEntryPoint);
        printf("- Image Base: 0x%llX\n", ntHeaders64Pointer->OptionalHeader.ImageBase);
        printf("- Section Alignment: %ld Bytes\n", ntHeaders64Pointer->OptionalHeader.SectionAlignment);
        printf("- File Alignment: %ld Bytes\n", ntHeaders64Pointer->OptionalHeader.FileAlignment);
        printf("- Subsystem: ");
        PrintSubSystem(ntHeaders64Pointer->OptionalHeader.Subsystem);
        printf("- Size of Image: %.2lf KB\n", (double)ntHeaders64Pointer->OptionalHeader.SizeOfImage / 1024);
        printf("- Size of Headers: %ld Bytes\n", ntHeaders64Pointer->OptionalHeader.SizeOfHeaders);
    
        is64 = TRUE;
        importDirectory = ntHeaders64Pointer->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        printf("- Target Architecture: Unknown!\nExiting..\n");

        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);

        return -1;
    }
    printf("-------------------------------------------------\n");


    PIMAGE_SECTION_HEADER sectionHeaderPointer = IMAGE_FIRST_SECTION(ntHeadersPointer);
    
    if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0) {
        printf("\nNo Import Directory found in the target program!\n");
    } else {
        printf("\nImport Address Table:");
        
        DWORD importFileOffset = RvaToFileOffset(sectionHeaderPointer, numberOfSections, importDirectory.VirtualAddress);
        if (importFileOffset == 0) {
            printf("    Failed to resolve Import Directory RVA (0x%08lX) to file offset\n", importDirectory.VirtualAddress);
        } else {
            PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(basePointer + importFileOffset);

            int dllIndex = 1;

            while (importDescriptor->Name != 0) {
                DWORD dllNameOffset = RvaToFileOffset(sectionHeaderPointer, numberOfSections, importDescriptor->Name);
            
                if (dllNameOffset != 0) {
                    char* dllName = (char*)(basePointer + dllNameOffset);
                    printf("\n  DLL #%d: %s\n", dllIndex++, dllName);

                    DWORD thunkRVA = importDescriptor->OriginalFirstThunk ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk;
                    DWORD thunkOffset = RvaToFileOffset(sectionHeaderPointer, numberOfSections, thunkRVA);

                    if (thunkOffset != 0) {
                        int thunkIdx = 0;

                        if (is64) {
                            PIMAGE_THUNK_DATA64 thunk64 = (PIMAGE_THUNK_DATA64)(basePointer + thunkOffset);
                            while (thunk64->u1.AddressOfData != 0) {
                                if (thunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                                    WORD ordinal = (WORD)(thunk64->u1.Ordinal & 0xFFFF);
                                    printf("    [%04d] ByOrdinal -> Ordinal #%u\n", thunkIdx++, ordinal);
                                } else {
                                    DWORD importByNameRVA = (DWORD)thunk64->u1.AddressOfData;
                                    DWORD importByNameOffset = RvaToFileOffset(sectionHeaderPointer, numberOfSections, importByNameRVA);
                                    
                                    if (importByNameOffset != 0) {
                                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(basePointer + importByNameOffset);
                                        printf("    [%04d] ByName -> %s (Hint: %u)\n", thunkIdx++, importByName->Name, importByName->Hint);
                                    }
                                }
                                thunk64++;
                            }
                        } else {
                            PIMAGE_THUNK_DATA32 thunk32 = (PIMAGE_THUNK_DATA32)(basePointer + thunkOffset);
                            while (thunk32->u1.AddressOfData != 0) {
                                if (thunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                                    WORD ordinal = (WORD)(thunk32->u1.Ordinal & 0xFFFF);
                                    printf("    [%04d] ByOrdinal -> Ordinal #%u\n", thunkIdx++, ordinal);
                                } else {
                                    DWORD importByNameRVA = (DWORD)thunk32->u1.AddressOfData;
                                    DWORD importByNameOffset = RvaToFileOffset(sectionHeaderPointer, numberOfSections, importByNameRVA);
                                    
                                    if (importByNameOffset != 0) {
                                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(basePointer + importByNameOffset);
                                        printf("    [%04d] ByName -> %s (Hint: %u)\n", thunkIdx++, importByName->Name, importByName->Hint);
                                    }
                                }
                                thunk32++;
                            }
                        }
                    }
                }
                importDescriptor++;
            }
        }
    }

    CloseHandle(fileMappingHandle);
    CloseHandle(fileHandle);

    return 0;
}

bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime) {
    time_t rawTime = (time_t)originalTime;
    struct tm *utc_time;

    utc_time = gmtime(&rawTime);

    if (utc_time == NULL) {
        printf("Couldn't format the date!\n");

        return false;
    }

    size_t result = strftime(formattedTime, stringSize, "%a %b %d %H:%M:%S %Y UTC", utc_time);
    
    if (result == 0) {
        return false;
    }

    return true;
}

void PrintFileCharacteristics(WORD fileCharacteristics, int characteristicsTableSize) {
    BOOL isFirst = TRUE;

    printf("0x%X (", fileCharacteristics);
    for (int i = 0; i < characteristicsTableSize; i++) {
        if ((fileCharacteristics & FileCharacteristicsTable[i].flag) == FileCharacteristicsTable[i].flag) {
            if (!isFirst) {
                printf(", ");
            }

            printf("%s", FileCharacteristicsTable[i].name);
            isFirst = FALSE;
        }
    }

    if (isFirst) {
        printf("None");
    }
    printf(")\n");
}

void PrintSubSystem(WORD subSystem) {
    if (subSystem == IMAGE_SUBSYSTEM_UNKNOWN) {
        printf("Unknown\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_NATIVE) {
        printf("Device Driver / Native System Process\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
       printf("Windows GUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        printf("Windows CUI (Console)\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_OS2_CUI) {
        printf("OS/2 CUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_POSIX_CUI) {
        printf("POSIX CUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) {
        printf("Windows CE System\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_APPLICATION) {
        printf("EFI Application\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
        printf("EFI Driver with Boot Services\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
        printf("EFI Driver with Run-Time Services\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_ROM) {
        printf("EFI ROM Image\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_XBOX) {
        printf("Xbox System\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) {
        printf("Windows Boot Application\n");
    }
}

DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER sectionHeaders, WORD numberOfSections, DWORD rva) {
    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD secVirtualAddress = sectionHeaders[i].VirtualAddress;
        DWORD secSize = (sectionHeaders[i].Misc.VirtualSize > sectionHeaders[i].SizeOfRawData) ? 
                        sectionHeaders[i].Misc.VirtualSize : sectionHeaders[i].SizeOfRawData;
        
        if (rva >= secVirtualAddress && rva < (secVirtualAddress + secSize)) {
            return (rva - secVirtualAddress) + sectionHeaders[i].PointerToRawData;
        }
    }
    return 0;
}