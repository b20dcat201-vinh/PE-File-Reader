#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

typedef unsigned long long QWORD;

IMAGE_DOS_HEADER dos_header;
IMAGE_FILE_HEADER file_header;

DWORD importDirectoryRva;
DWORD exportDirectoryRva;

char *sizeStr(int n);
char *sectionOfRva(IMAGE_SECTION_HEADER *section_headers, int rva);
char *machineTypes(int n);
char *magicNumber(int n);
char *subSystem(int n);

void dosHeaderDisplay();
void ntHeaderDisPlay32(IMAGE_NT_HEADERS32 nt_header);
void ntHeaderDisPlay64(IMAGE_NT_HEADERS64 nt_header);
void fileHeaderCharacteristics(int characteristicValue);
void fileHeaderDisplay();
void optionalHeaderDllCharacteristics(int dllCharacteristicValue);

void optionalHeaderDisplay64(IMAGE_NT_HEADERS64 nt_header, IMAGE_SECTION_HEADER *section_headers);
void optionalHeaderDisplay32(IMAGE_NT_HEADERS32 nt_header, IMAGE_SECTION_HEADER *section_headers);

void importFunctionsDisplay64(FILE *file, IMAGE_SECTION_HEADER *section_header, int importDirectoryRva);
void importFunctionsDisplay32(FILE *file, IMAGE_SECTION_HEADER *section_header, int importDirectoryRva);

void dataDirectoriesDisplay64(IMAGE_NT_HEADERS64 nt_headers, IMAGE_SECTION_HEADER *section_headers);
void dataDirectoriesDisplay32(IMAGE_NT_HEADERS32 nt_headers, IMAGE_SECTION_HEADER *section_headers);

void sectionHeadersDisplay(IMAGE_SECTION_HEADER *section_headers);
void importDirectoryDisplay(FILE *file, IMAGE_SECTION_HEADER *section_header, int importDirectoryRva, int magic);
int readValueAtOffset(FILE *file, int offset, int quantity);

DWORD convertRvaToOffset(IMAGE_SECTION_HEADER *section_headers, QWORD rva);

void exportDirectoryDisplay(FILE *file, IMAGE_SECTION_HEADER *section_header, int exportDirectoryRva, int magic);
void exportFunctionDisplay(FILE *file, IMAGE_SECTION_HEADER *section_header, int export_directory_rva);

int main()
{
    char filePath[256];
    FILE *file;
    printf("Enter the file path: ");
    fgets(filePath, sizeof(filePath), stdin);
    // Remove '\n' by Enter at Keyboard
    size_t len = strlen(filePath);
    if (len > 0 && filePath[len - 1] == '\n')
    {
        filePath[len - 1] = '\0';
    }
    file = fopen(filePath, "rb");

    // Read Dos Headers
    fread(&dos_header, sizeof(dos_header), 1, file);
    dosHeaderDisplay();
    
    if (dos_header.e_magic != 0x5A4D){
        printf("File not Executable format\n");
        return 0;
    }

    // Read File Header
    fseek(file, dos_header.e_lfanew + 4, SEEK_SET);
    fread(&file_header, sizeof(file_header), 1, file);

    IMAGE_SECTION_HEADER section_headers[file_header.NumberOfSections];
    int magic = readValueAtOffset(file, dos_header.e_lfanew + 24, 2);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    { // 0x20B => PE64
        // Read NT64 Headers
        IMAGE_NT_HEADERS64 nt_header;
        fseek(file, dos_header.e_lfanew, SEEK_SET);
        fread(&nt_header, sizeof(nt_header), 1, file);

        // Read Section Header
        int sectionHeaderOffset = dos_header.e_lfanew + 4 + 20 + IMAGE_SIZEOF_NT_OPTIONAL64_HEADER;
        fseek(file, sectionHeaderOffset, SEEK_SET);
        fread(&section_headers, sizeof(section_headers), 1, file);

        // Display
        ntHeaderDisPlay64(nt_header);
        fileHeaderDisplay();
        optionalHeaderDisplay64(nt_header, section_headers);
        dataDirectoriesDisplay64(nt_header, section_headers);
        importDirectoryRva = nt_header.OptionalHeader.DataDirectory[1].VirtualAddress;
        exportDirectoryRva = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    { // 0x10B => PE32
        // Read NT32 Headers
        IMAGE_NT_HEADERS32 nt_header;
        fseek(file, dos_header.e_lfanew, SEEK_SET);
        fread(&nt_header, sizeof(nt_header), 1, file);

        // Read Section Header
        int sectionHeaderOffset = dos_header.e_lfanew + 4 + 20 + IMAGE_SIZEOF_NT_OPTIONAL32_HEADER;
        fseek(file, sectionHeaderOffset, SEEK_SET);
        fread(&section_headers, sizeof(section_headers), 1, file);

        // Display
        ntHeaderDisPlay32(nt_header);
        fileHeaderDisplay();
        optionalHeaderDisplay32(nt_header, section_headers);
        dataDirectoriesDisplay32(nt_header, section_headers);
        importDirectoryRva = nt_header.OptionalHeader.DataDirectory[1].VirtualAddress;
        exportDirectoryRva = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress;
    }

    sectionHeadersDisplay(section_headers);

    printf("\nPress any key to continue...");
    char c = getchar();

    if (exportDirectoryRva != 0)
    {
        exportDirectoryDisplay(file, section_headers, exportDirectoryRva, magic);
    }

    if (importDirectoryRva != 0)
    {
        importDirectoryDisplay(file, section_headers, importDirectoryRva, magic);
    }

    fclose(file);
    return 0;
}

void exportDirectoryDisplay(FILE *file, IMAGE_SECTION_HEADER *section_header, int export_directory_rva, int magic)
{

    IMAGE_EXPORT_DIRECTORY export_directory;
    DWORD export_directory_offset = convertRvaToOffset(section_header, export_directory_rva);

    fseek(file, export_directory_offset, SEEK_SET);
    fread(&export_directory, sizeof(IMAGE_EXPORT_DIRECTORY), 1, file);

    printf("\n-----Export Directory-----\n");
    DWORD export_directory_name_offset = convertRvaToOffset(section_header, export_directory.Name);
    fseek(file, export_directory_name_offset, SEEK_SET);
    char name[256];
    fread(&name, sizeof(name), 1, file);
    printf("Export Directory Name: \033[1;32m%s\033[0m\n", name);
    printf("\033[1;31m%-30s %-15s %-10s %s\033[0m\n", "Member", "Offset", "Size", "Value");
    printf("%-30s %08X%-7s %-10s %08X\n", "Characteristics", export_directory_offset, "", sizeStr(sizeof(export_directory.Characteristics)), export_directory.Characteristics);
    printf("%-30s %08X%-7s %-10s %08X\n", "TimeDateStamp", export_directory_offset + 4, "", sizeStr(sizeof(export_directory.TimeDateStamp)), export_directory.TimeDateStamp);
    printf("%-30s %08X%-7s %-10s %04X\n", "MajorVersion", export_directory_offset + 8, "", sizeStr(sizeof(export_directory.MajorVersion)), export_directory.MajorVersion);
    printf("%-30s %08X%-7s %-10s %04X\n", "MinorVersion", export_directory_offset + 10, "", sizeStr(sizeof(export_directory.MinorVersion)), export_directory.MinorVersion);
    printf("%-30s %08X%-7s %-10s %08X\n", "Name", export_directory_offset + 12, "", sizeStr(sizeof(export_directory.Name)), export_directory.Name);
    printf("%-30s %08X%-7s %-10s %08X\n", "Base", export_directory_offset + 16, "", sizeStr(sizeof(export_directory.Base)), export_directory.Base);
    printf("%-30s %08X%-7s %-10s %08X\n", "NumberOfFunctions", export_directory_offset + 20, "", sizeStr(sizeof(export_directory.NumberOfFunctions)), export_directory.NumberOfFunctions);
    printf("%-30s %08X%-7s %-10s %08X\n", "NumberOfNames", export_directory_offset + 24, "", sizeStr(sizeof(export_directory.NumberOfNames)), export_directory.NumberOfNames);
    printf("%-30s %08X%-7s %-10s %08X\n", "AddressOffFunctions", export_directory_offset + 28, "", sizeStr(sizeof(export_directory.AddressOfFunctions)), export_directory.AddressOfFunctions);
    printf("%-30s %08X%-7s %-10s %08X\n", "AddressOfNames", export_directory_offset + 32, "", sizeStr(sizeof(export_directory.AddressOfNames)), export_directory.AddressOfNames);
    printf("%-30s %08X%-7s %-10s %08X\n", "AddressOfNameOrdinals", export_directory_offset + 36, "", sizeStr(sizeof(export_directory.AddressOfNameOrdinals)), export_directory.AddressOfNameOrdinals);

    printf("\nPress any key to continue...");
    char c = getchar();

    exportFunctionDisplay(file, section_header, export_directory_rva);

    printf("\nPress any key to continue...");
    c = getchar();
}

typedef struct _EXPORT_FUNCTION{
    DWORD NameRVA;
    DWORD FunctionRVA;
    DWORD Ordinal;
    WORD NameOrdinal;
    char *Name;
} EXPORT_FUNCTION;

int compareAsc(const void *a, const void *b) {
    EXPORT_FUNCTION *functionA = (EXPORT_FUNCTION*)a;
    EXPORT_FUNCTION *functionB = (EXPORT_FUNCTION*)b;
    return (int) (functionA->NameOrdinal - functionB->NameOrdinal);
}

void exportFunctionDisplay(FILE *file, IMAGE_SECTION_HEADER *section_header, int export_directory_rva)
{
    IMAGE_EXPORT_DIRECTORY export_directory;
    DWORD export_directory_offset = convertRvaToOffset(section_header, export_directory_rva);

    fseek(file, export_directory_offset, SEEK_SET);
    fread(&export_directory, sizeof(IMAGE_EXPORT_DIRECTORY), 1, file);

    DWORD name_offset = convertRvaToOffset(section_header, export_directory.AddressOfNames);
    DWORD name_ordinal_offset = convertRvaToOffset(section_header, export_directory.AddressOfNameOrdinals);
    DWORD function_offset = convertRvaToOffset(section_header, export_directory.AddressOfFunctions);

    printf("\n-----Export Function-----\n");
    printf("\033[1;31m%-15s %-15s %-15s %-10s %s\033[0m\n", "Ordinal", "Function RVA", "Name Ordinal", "Name RVA", "Name");

    EXPORT_FUNCTION *export_function = (EXPORT_FUNCTION*) malloc(export_directory.NumberOfNames * sizeof(EXPORT_FUNCTION));
    
    for (int i=0; i<export_directory.NumberOfNames; i++){
        // Read Name Ordinal
        fseek(file, name_ordinal_offset, SEEK_SET);
        WORD name_ordinal;
        fread(&name_ordinal, sizeof(WORD), 1, file);
        name_ordinal_offset += 2;

        // Read Function RVA
        fseek(file, function_offset + sizeof(function_offset) * name_ordinal, SEEK_SET);
        DWORD function_rva;
        fread(&function_rva, sizeof(function_rva), 1, file);
        export_function[i].FunctionRVA = function_rva;

        // Read Name RVA
        fseek(file, name_offset, SEEK_SET);
        DWORD name_rva;
        fread(&name_rva, sizeof(name_rva), 1, file);

        export_function[i].Ordinal = name_ordinal + export_directory.Base;
        export_function[i].FunctionRVA = function_rva;
        export_function[i].NameOrdinal = name_ordinal;
        export_function[i].NameRVA = name_rva;

        // Read Name
        DWORD function_name_offset = convertRvaToOffset(section_header, name_rva);
        fseek(file, function_name_offset, SEEK_SET);
        char c;
        char *test_name_str = (char*)malloc(1);
        unsigned int test_name_length = 0;
        while (fread(&c, 1, 1, file) && c != 0)
        {
            test_name_length++;
            test_name_str = (char*)realloc(test_name_str, test_name_length+1);
            test_name_str[test_name_length-1] = c;
            test_name_str[test_name_length] = '\0';
        }
        export_function[i].Name = test_name_str;

        fseek(file, name_offset += sizeof(DWORD), SEEK_SET);
    }

    qsort(export_function, export_directory.NumberOfNames, sizeof(EXPORT_FUNCTION), compareAsc);

    for (int i=0; i<export_directory.NumberOfNames; i++){
        printf("%08X%-7s ", export_function[i].Ordinal, "");
        printf("%08X%-7s ", export_function[i].FunctionRVA, "");
        printf("%04X%-11s ", export_function[i].NameOrdinal, "");
        printf("%08X%-2s ", export_function[i].NameRVA, "");
        printf("%s", export_function[i].Name);
        free(export_function[i].Name);
        printf("\n");
    }

    free(export_function);
}

char *subSystem(int n)
{
    char *str;
    switch (n)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN:
        str = "Unknown Value";
        break;
    case IMAGE_SUBSYSTEM_NATIVE:
        str = "Native";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        str = "Windows GUI";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        str = "Windows Console";
        break;
    case IMAGE_SUBSYSTEM_OS2_CUI:
        str = "OS/2 Console";
        break;
    case IMAGE_SUBSYSTEM_POSIX_CUI:
        str = "Posix Console";
        break;
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
        str = "Native Win9x Driver";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        str = "Win CE";
        break;
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        str = "EFI Application";
        break;
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        str = "EFI Boot Driver";
        break;
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        str = "EFI Runtime Driver";
        break;
    case IMAGE_SUBSYSTEM_EFI_ROM:
        str = "EFI ROM";
        break;
    case IMAGE_SUBSYSTEM_XBOX:
        str = "XBox";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        str = "Windows Boot Application";
        break;
    default:
        str = "";
        break;
    }
    return str;
}

void dosHeaderDisplay()
{
    printf("\n-----Dos Headers-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-10s\033[0m\n", "Member", "Offset", "Size", "Value");
    printf("%-40s %08X%-2s %-10s %04X\n", "e_magic", 0, "", sizeStr(sizeof(dos_header.e_magic)), dos_header.e_magic);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_cblp", 2, "", sizeStr(sizeof(dos_header.e_cblp)), dos_header.e_cblp);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_cp", 2 * 2, "", sizeStr(sizeof(dos_header.e_cp)), dos_header.e_cp);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_crlc", 2 * 3, "", sizeStr(sizeof(dos_header.e_crlc)), dos_header.e_crlc);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_cparhdr", 2 * 4, "", sizeStr(sizeof(dos_header.e_cparhdr)), dos_header.e_cparhdr);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_minalloc", 2 * 5, "", sizeStr(sizeof(dos_header.e_minalloc)), dos_header.e_minalloc);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_maxalloc", 2 * 6, "", sizeStr(sizeof(dos_header.e_maxalloc)), dos_header.e_maxalloc);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_ss", 2 * 7, "", sizeStr(sizeof(dos_header.e_ss)), dos_header.e_ss);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_sp", 2 * 8, "", sizeStr(sizeof(dos_header.e_sp)), dos_header.e_sp);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_csum", 2 * 9, "", sizeStr(sizeof(dos_header.e_csum)), dos_header.e_csum);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_ip", 2 * 10, "", sizeStr(sizeof(dos_header.e_ip)), dos_header.e_ip);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_cs", 2 * 11, "", sizeStr(sizeof(dos_header.e_cs)), dos_header.e_cs);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_lfarlc", 2 * 12, "", sizeStr(sizeof(dos_header.e_lfarlc)), dos_header.e_lfarlc);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_ovno", 2 * 13, "", sizeStr(sizeof(dos_header.e_ovno)), dos_header.e_ovno);

    printf("%-40s %08X%-2s %-10s %04X\n", "e_res", 2 * 14, "", sizeStr(sizeof(dos_header.e_res[0])), dos_header.e_res[0]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 15, "", sizeStr(sizeof(dos_header.e_res[1])), dos_header.e_res[1]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 16, "", sizeStr(sizeof(dos_header.e_res[2])), dos_header.e_res[2]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 17, "", sizeStr(sizeof(dos_header.e_res[3])), dos_header.e_res[3]);

    printf("%-40s %08X%-2s %-10s %04X\n", "e_oemid", 2 * 18, "", sizeStr(sizeof(dos_header.e_oemid)), dos_header.e_oemid);
    printf("%-40s %08X%-2s %-10s %04X\n", "e_oeminfo", 2 * 19, "", sizeStr(sizeof(dos_header.e_oeminfo)), dos_header.e_oeminfo);

    printf("%-40s %08X%-2s %-10s %04X\n", "e_res2", 2 * 20, "", sizeStr(sizeof(dos_header.e_res2[0])), dos_header.e_res2[0]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 21, "", sizeStr(sizeof(dos_header.e_res2[1])), dos_header.e_res2[1]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 22, "", sizeStr(sizeof(dos_header.e_res2[2])), dos_header.e_res2[2]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 23, "", sizeStr(sizeof(dos_header.e_res2[3])), dos_header.e_res2[3]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 24, "", sizeStr(sizeof(dos_header.e_res2[4])), dos_header.e_res2[4]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 25, "", sizeStr(sizeof(dos_header.e_res2[5])), dos_header.e_res2[5]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 26, "", sizeStr(sizeof(dos_header.e_res2[6])), dos_header.e_res2[6]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 27, "", sizeStr(sizeof(dos_header.e_res2[7])), dos_header.e_res2[7]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 28, "", sizeStr(sizeof(dos_header.e_res2[8])), dos_header.e_res2[8]);
    printf("%-40s %08X%-2s %-10s %04X\n", "", 2 * 29, "", sizeStr(sizeof(dos_header.e_res2[9])), dos_header.e_res2[9]);

    printf("%-40s %08X%-2s %-10s %08X\n", "e_lfanew", 60, "", sizeStr(sizeof(dos_header.e_lfanew)), dos_header.e_lfanew);
}

void ntHeaderDisPlay32(IMAGE_NT_HEADERS32 nt_header)
{
    printf("\n-----Nt Headers-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-10s\033[0m\n", "Member", "Offset", "Size", "Value");
    printf("%-40s %08X%-2s %-10s %08X\n", "Signature", dos_header.e_lfanew, "", sizeStr(sizeof(nt_header.Signature)), nt_header.Signature);
}

void ntHeaderDisPlay64(IMAGE_NT_HEADERS64 nt_header)
{
    printf("\n-----Nt Headers-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-10s\033[0m\n", "Member", "Offset", "Size", "Value");
    printf("%-40s %08X%-2s %-10s %08X\n", "Signature", dos_header.e_lfanew, "", sizeStr(sizeof(nt_header.Signature)), nt_header.Signature);
}

void fileHeaderCharacteristics(int characteristicValue)
{
    if (characteristicValue & IMAGE_FILE_EXECUTABLE_IMAGE)
        printf("%-84s%s\n", "", "File is executable");
    if (characteristicValue & IMAGE_FILE_DLL)
        printf("%-84s%s\n", "", "File is a DLL");
    if (characteristicValue & IMAGE_FILE_SYSTEM)
        printf("%-84s%s\n", "", "System File");
    if (characteristicValue & IMAGE_FILE_RELOCS_STRIPPED)
        printf("%-84s%s\n", "", "Relocation info stripped from file");
    if (characteristicValue & IMAGE_FILE_LINE_NUMS_STRIPPED)
        printf("%-84s%s\n", "", "Line numbers stripped from file");
    if (characteristicValue & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
        printf("%-84s%s\n", "", "Local symbols stripped from file");
    if (characteristicValue & IMAGE_FILE_AGGRESIVE_WS_TRIM)
        printf("%-84s%s\n", "", "Agressively trim working set");
    if (characteristicValue & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        printf("%-84s%s\n", "", "App can handle > 2gb address space");
    if (characteristicValue & IMAGE_FILE_BYTES_REVERSED_LO)
        printf("%-84s%s\n", "", "Bytes of machine word are reversed (low)");
    if (characteristicValue & IMAGE_FILE_32BIT_MACHINE)
        printf("%-84s%s\n", "", "32 bit word machine");
    if (characteristicValue & IMAGE_FILE_DEBUG_STRIPPED)
        printf("%-84s%s\n", "", "Debugging info stripped from file in .DBG file");
    if (characteristicValue & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
        printf("%-84s%s\n", "", "If Image is on removable media, copy and run from the swap file");
    if (characteristicValue & IMAGE_FILE_NET_RUN_FROM_SWAP)
        printf("%-84s%s\n", "", "If Image is on Net, copy and run from the swap file");
    if (characteristicValue & IMAGE_FILE_UP_SYSTEM_ONLY)
        printf("%-84s%s\n", "", "File should only be run on a UP machine");
    if (characteristicValue & IMAGE_FILE_BYTES_REVERSED_HI)
        printf("%-84s%s\n", "", "Bytes of machine word are reversed (high)");
}

void fileHeaderDisplay()
{
    int firstOffset = dos_header.e_lfanew + 4;
    printf("\n-----File Headers-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-20s %-15s\033[0m\n", "Member", "Offset", "Size", "Value", "Meaning");
    printf("%-40s %08X%-2s %-10s %04X%-16s %-15s\n", "Machine", firstOffset, "", sizeStr(2), file_header.Machine, "", machineTypes(file_header.Machine));
    printf("%-40s %08X%-2s %-10s %04X\n", "NumberOfSections", firstOffset + 2, "", sizeStr(2), file_header.NumberOfSections);
    printf("%-40s %08X%-2s %-10s %08X\n", "TimeDateStamp", firstOffset + 4, "", sizeStr(4), file_header.TimeDateStamp);
    printf("%-40s %08X%-2s %-10s %08X\n", "PointerToSymbolTable", firstOffset + 8, "", sizeStr(4), file_header.PointerToSymbolTable);
    printf("%-40s %08X%-2s %-10s %08X\n", "NumberOfSymbols", firstOffset + 12, "", sizeStr(4), file_header.NumberOfSymbols);
    printf("%-40s %08X%-2s %-10s %04X\n", "SizeOfOptionalHeader", firstOffset + 16, "", sizeStr(2), file_header.SizeOfOptionalHeader);
    printf("%-40s %08X%-2s %-10s %04X%-16s %s\n", "Characteristics", firstOffset + 18, "", sizeStr(2), file_header.Characteristics, "", "----------");
    fileHeaderCharacteristics(file_header.Characteristics);
}

void optionalHeaderDllCharacteristics(int dllCharacteristicValue)
{
    if (dllCharacteristicValue & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        printf("%-84s%s\n", "", "DLL can move");
    if (dllCharacteristicValue & IMAGE_FILE_DLL)
        printf("%-84s%s\n", "", "Code Integrity Image");
    if (dllCharacteristicValue & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        printf("%-84s%s\n", "", "Image is NX compatible");
    if (dllCharacteristicValue & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
        printf("%-84s%s\n", "", "Image understands isolation and doesn't want it");
    if (dllCharacteristicValue & IMAGE_DLLCHARACTERISTICS_NO_SEH)
        printf("%-84s%s\n", "", "Image does not use SEH");
    if (dllCharacteristicValue & IMAGE_DLLCHARACTERISTICS_NO_BIND)
        printf("%-84s%s\n", "", "Do not bind this image");
    if (dllCharacteristicValue & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
        printf("%-84s%s\n", "", "Drivers uses WDM model");
    if (dllCharacteristicValue & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
        printf("%-84s%s\n", "", "Terminal Server Aware");
}

void optionalHeaderDisplay32(IMAGE_NT_HEADERS32 nt_header, IMAGE_SECTION_HEADER *section_headers)
{
    int firstOffset = dos_header.e_lfanew + 24;
    printf("\n-----Optional Headers-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-20s %-15s\033[0m\n", "Member", "Offset", "Size", "Value", "Meaning");
    printf("%-40s %08X%-2s %-10s %04X%-16s %-15s\n", "Magic", firstOffset, "", sizeStr(2), nt_header.OptionalHeader.Magic, "", magicNumber(nt_header.OptionalHeader.Magic));

    printf("%-40s %08X%-2s %-10s %02X\n", "MajorLinkerVersion", firstOffset + 2, "", sizeStr(1), nt_header.OptionalHeader.MajorLinkerVersion);
    printf("%-40s %08X%-2s %-10s %02X\n", "MinorLinkerVersion", firstOffset + 3, "", sizeStr(1), nt_header.OptionalHeader.MinorLinkerVersion);

    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfCode", firstOffset + 4, "", sizeStr(4), nt_header.OptionalHeader.SizeOfCode);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfInitializedData", firstOffset + 8, "", sizeStr(4), nt_header.OptionalHeader.SizeOfInitializedData);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfUninitializedData", firstOffset + 12, "", sizeStr(4), nt_header.OptionalHeader.SizeOfUninitializedData);

    printf("%-40s %08X%-2s %-10s %08X%-12s %s\n", "AddressOfEntryPoint", firstOffset + 16, "", sizeStr(4), nt_header.OptionalHeader.AddressOfEntryPoint, "", sectionOfRva(section_headers, nt_header.OptionalHeader.AddressOfEntryPoint));
    printf("%-40s %08X%-2s %-10s %08X\n", "BaseOfCode", firstOffset + 20, "", sizeStr(4), nt_header.OptionalHeader.BaseOfCode);
    printf("%-40s %08X%-2s %-10s %08X\n", "BaseOfData", firstOffset + 24, "", sizeStr(4), nt_header.OptionalHeader.BaseOfData);

    printf("%-40s %08X%-2s %-10s %08X\n", "ImageBase", firstOffset + 28, "", sizeStr(4), nt_header.OptionalHeader.ImageBase);
    printf("%-40s %08X%-2s %-10s %08X\n", "SectionAlignment", firstOffset + 32, "", sizeStr(4), nt_header.OptionalHeader.SectionAlignment);
    printf("%-40s %08X%-2s %-10s %08X\n", "FileAlignment", firstOffset + 36, "", sizeStr(4), nt_header.OptionalHeader.FileAlignment);

    printf("%-40s %08X%-2s %-10s %04X\n", "MajorOperatingSystemVersion", firstOffset + 40, "", sizeStr(2), nt_header.OptionalHeader.MajorOperatingSystemVersion);
    printf("%-40s %08X%-2s %-10s %04X\n", "MinorOperatingSystemVersion", firstOffset + 42, "", sizeStr(2), nt_header.OptionalHeader.MinorOperatingSystemVersion);

    printf("%-40s %08X%-2s %-10s %04X\n", "MajorImageVersion", firstOffset + 44, "", sizeStr(2), nt_header.OptionalHeader.MajorImageVersion);
    printf("%-40s %08X%-2s %-10s %04X\n", "MinorImageVersion", firstOffset + 46, "", sizeStr(2), nt_header.OptionalHeader.MinorImageVersion);

    printf("%-40s %08X%-2s %-10s %04X\n", "MajorSubsystemVersion", firstOffset + 48, "", sizeStr(2), nt_header.OptionalHeader.MajorSubsystemVersion);
    printf("%-40s %08X%-2s %-10s %04X\n", "MinorSubsystemVersion", firstOffset + 50, "", sizeStr(2), nt_header.OptionalHeader.MinorSubsystemVersion);

    printf("%-40s %08X%-2s %-10s %08X\n", "Win32VersionValue", firstOffset + 52, "", sizeStr(4), nt_header.OptionalHeader.Win32VersionValue);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfImage", firstOffset + 56, "", sizeStr(4), nt_header.OptionalHeader.SizeOfImage);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfHeaders", firstOffset + 60, "", sizeStr(4), nt_header.OptionalHeader.SizeOfHeaders);
    printf("%-40s %08X%-2s %-10s %08X\n", "CheckSum", firstOffset + 64, "", sizeStr(4), nt_header.OptionalHeader.CheckSum);
    printf("%-40s %08X%-2s %-10s %04X%-16s %-15s\n", "Subsystem", firstOffset + 68, "", sizeStr(2), nt_header.OptionalHeader.Subsystem, "", subSystem(nt_header.OptionalHeader.Subsystem));

    printf("%-40s %08X%-2s %-10s %04X%-16s %s\n", "DllCharacteristics", firstOffset + 70, "", sizeStr(2), nt_header.OptionalHeader.DllCharacteristics, "", "----------");
    optionalHeaderDllCharacteristics(nt_header.OptionalHeader.DllCharacteristics);

    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfStackReserve", firstOffset + 72, "", sizeStr(4), nt_header.OptionalHeader.SizeOfStackReserve);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfStackCommit", firstOffset + 76, "", sizeStr(4), nt_header.OptionalHeader.SizeOfStackCommit);

    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfHeapReserve", firstOffset + 80, "", sizeStr(4), nt_header.OptionalHeader.SizeOfHeapReserve);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfHeapCommit", firstOffset + 84, "", sizeStr(4), nt_header.OptionalHeader.SizeOfHeapCommit);

    printf("%-40s %08X%-2s %-10s %08X\n", "LoaderFlags", firstOffset + 88, "", sizeStr(4), nt_header.OptionalHeader.LoaderFlags);
    printf("%-40s %08X%-2s %-10s %08X\n", "NumberOfRvaAndSizes", firstOffset + 92, "", sizeStr(4), nt_header.OptionalHeader.NumberOfRvaAndSizes);
}

void optionalHeaderDisplay64(IMAGE_NT_HEADERS64 nt_header, IMAGE_SECTION_HEADER *section_headers)
{
    int firstOffset = dos_header.e_lfanew + 24;
    // Standard
    printf("\n-----Optional Headers-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-20s %-15s\033[0m\n", "Member", "Offset", "Size", "Value", "Meaning");
    printf("%-40s %08X%-2s %-10s %04X%-16s %-15s\n", "Magic", firstOffset, "", sizeStr(2), nt_header.OptionalHeader.Magic, "", magicNumber(nt_header.OptionalHeader.Magic));

    printf("%-40s %08X%-2s %-10s %02X\n", "MajorLinkerVersion", firstOffset + 2, "", sizeStr(1), nt_header.OptionalHeader.MajorLinkerVersion);
    printf("%-40s %08X%-2s %-10s %02X\n", "MinorLinkerVersion", firstOffset + 3, "", sizeStr(1), nt_header.OptionalHeader.MinorLinkerVersion);

    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfCode", firstOffset + 4, "", sizeStr(4), nt_header.OptionalHeader.SizeOfCode);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfInitializedData", firstOffset + 8, "", sizeStr(4), nt_header.OptionalHeader.SizeOfInitializedData);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfUninitializedData", firstOffset + 12, "", sizeStr(4), nt_header.OptionalHeader.SizeOfUninitializedData);

    printf("%-40s %08X%-2s %-10s %08X%-12s %s\n", "AddressOfEntryPoint", firstOffset + 16, "", sizeStr(4), nt_header.OptionalHeader.AddressOfEntryPoint, "", sectionOfRva(section_headers, nt_header.OptionalHeader.AddressOfEntryPoint));
    printf("%-40s %08X%-2s %-10s %08X\n", "BaseOfCode", firstOffset + 20, "", sizeStr(4), nt_header.OptionalHeader.BaseOfCode);

    // Specific
    printf("%-40s %08X%-2s %-10s %016llX\n", "ImageBase", firstOffset + 24, "", sizeStr(8), nt_header.OptionalHeader.ImageBase);
    printf("%-40s %08X%-2s %-10s %08X\n", "SectionAlignment", firstOffset + 32, "", sizeStr(4), nt_header.OptionalHeader.SectionAlignment);
    printf("%-40s %08X%-2s %-10s %08X\n", "FileAlignment", firstOffset + 36, "", sizeStr(4), nt_header.OptionalHeader.FileAlignment);

    printf("%-40s %08X%-2s %-10s %04X\n", "MajorOperatingSystemVersion", firstOffset + 40, "", sizeStr(2), nt_header.OptionalHeader.MajorOperatingSystemVersion);
    printf("%-40s %08X%-2s %-10s %04X\n", "MinorOperatingSystemVersion", firstOffset + 42, "", sizeStr(2), nt_header.OptionalHeader.MinorOperatingSystemVersion);

    printf("%-40s %08X%-2s %-10s %04X\n", "MajorImageVersion", firstOffset + 44, "", sizeStr(2), nt_header.OptionalHeader.MajorImageVersion);
    printf("%-40s %08X%-2s %-10s %04X\n", "MinorImageVersion", firstOffset + 46, "", sizeStr(2), nt_header.OptionalHeader.MinorImageVersion);

    printf("%-40s %08X%-2s %-10s %04X\n", "MajorSubsystemVersion", firstOffset + 48, "", sizeStr(2), nt_header.OptionalHeader.MajorSubsystemVersion);
    printf("%-40s %08X%-2s %-10s %04X\n", "MinorSubsystemVersion", firstOffset + 50, "", sizeStr(2), nt_header.OptionalHeader.MinorSubsystemVersion);

    printf("%-40s %08X%-2s %-10s %08X\n", "Win32VersionValue", firstOffset + 52, "", sizeStr(4), nt_header.OptionalHeader.Win32VersionValue);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfImage", firstOffset + 56, "", sizeStr(4), nt_header.OptionalHeader.SizeOfImage);
    printf("%-40s %08X%-2s %-10s %08X\n", "SizeOfHeaders", firstOffset + 60, "", sizeStr(4), nt_header.OptionalHeader.SizeOfHeaders);
    printf("%-40s %08X%-2s %-10s %08X\n", "CheckSum", firstOffset + 64, "", sizeStr(4), nt_header.OptionalHeader.CheckSum);
    printf("%-40s %08X%-2s %-10s %04X%-16s %-15s\n", "Subsystem", firstOffset + 68, "", sizeStr(2), nt_header.OptionalHeader.Subsystem, "", subSystem(nt_header.OptionalHeader.Subsystem));

    printf("%-40s %08X%-2s %-10s %04X%-16s %s\n", "DllCharacteristics", firstOffset + 70, "", sizeStr(2), nt_header.OptionalHeader.DllCharacteristics, "", "----------");
    optionalHeaderDllCharacteristics(nt_header.OptionalHeader.DllCharacteristics);

    printf("%-40s %08X%-2s %-10s %016X\n", "SizeOfStackReserve", firstOffset + 72, "", sizeStr(8), nt_header.OptionalHeader.SizeOfStackReserve);
    printf("%-40s %08X%-2s %-10s %016X\n", "SizeOfStackCommit", firstOffset + 80, "", sizeStr(8), nt_header.OptionalHeader.SizeOfStackCommit);

    printf("%-40s %08X%-2s %-10s %016X\n", "SizeOfHeapReserve", firstOffset + 88, "", sizeStr(8), nt_header.OptionalHeader.SizeOfHeapReserve);
    printf("%-40s %08X%-2s %-10s %016X\n", "SizeOfHeapCommit", firstOffset + 96, "", sizeStr(8), nt_header.OptionalHeader.SizeOfHeapCommit);

    printf("%-40s %08X%-2s %-10s %08X\n", "LoaderFlags", firstOffset + 104, "", sizeStr(4), nt_header.OptionalHeader.LoaderFlags);
    printf("%-40s %08X%-2s %-10s %08X\n", "NumberOfRvaAndSizes", firstOffset + 108, "", sizeStr(4), nt_header.OptionalHeader.NumberOfRvaAndSizes);
}

int readValueAtOffset(FILE *file, int offset, int quantity)
{
    int value;
    size_t bytesRead;
    fseek(file, offset, SEEK_SET);
    bytesRead = fread(&value, 1, quantity, file);
    return value;
}

char *sectionOfRva(IMAGE_SECTION_HEADER *section_headers, int rva)
{
    char *str;
    if (rva == 0)
    {
        str = "";
    }
    else
    {
        str = "Invalid";
    }

    int lowerLimit;
    int upperLimit;
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        lowerLimit = section_headers[i].VirtualAddress;
        if (section_headers[i].Misc.VirtualSize >= section_headers[i].SizeOfRawData)
        {
            upperLimit = lowerLimit + section_headers[i].Misc.VirtualSize;
        }
        else
        {
            upperLimit = lowerLimit + section_headers[i].Misc.VirtualSize + (section_headers[i].SizeOfRawData - section_headers[i].Misc.VirtualSize);
        }

        if (rva >= lowerLimit && rva < upperLimit && rva != 0)
        {
            str = section_headers[i].Name;
            break;
        }
    }
    return str;
}

void dataDirectoriesDisplay64(IMAGE_NT_HEADERS64 nt_headers, IMAGE_SECTION_HEADER *section_headers)
{
    int startOffset = dos_header.e_lfanew + 4 + 20 + IMAGE_SIZEOF_NT_OPTIONAL64_HEADER - IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY);
    IMAGE_OPTIONAL_HEADER64 optional_headers = nt_headers.OptionalHeader;
    printf("\n-----Data Directories-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-10s %s\033[0m\n", "Member", "Offset", "Size", "Value", "Section");
    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Export Directory RVA", startOffset, "", sizeStr(4), optional_headers.DataDirectory[0].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[0].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Export Directory Size", startOffset + 4 * 1, "", sizeStr(4), optional_headers.DataDirectory[0].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Import Directory RVA", startOffset + 4 * 2, "", sizeStr(4), optional_headers.DataDirectory[1].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[1].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Import Directory Size", startOffset + 4 * 3, "", sizeStr(4), optional_headers.DataDirectory[1].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Resource Directory RVA", startOffset + 4 * 4, "", sizeStr(4), optional_headers.DataDirectory[2].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[2].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Resource Directory Size", startOffset + 4 * 5, "", sizeStr(4), optional_headers.DataDirectory[2].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Exception Directory RVA", startOffset + 4 * 6, "", sizeStr(4), optional_headers.DataDirectory[3].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[3].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Exception Directory Size", startOffset + 4 * 7, "", sizeStr(4), optional_headers.DataDirectory[3].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Security Directory RVA", startOffset + 4 * 8, "", sizeStr(4), optional_headers.DataDirectory[4].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[4].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Security Directory Size", startOffset + 4 * 9, "", sizeStr(4), optional_headers.DataDirectory[4].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Relocation Directory RVA", startOffset + 4 * 10, "", sizeStr(4), optional_headers.DataDirectory[5].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[5].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Relocation Directory Size", startOffset + 4 * 11, "", sizeStr(4), optional_headers.DataDirectory[5].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Debug Directory RVA", startOffset + 4 * 12, "", sizeStr(4), optional_headers.DataDirectory[6].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[6].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Debug Directory Size", startOffset + 4 * 13, "", sizeStr(4), optional_headers.DataDirectory[6].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Architecture Directory RVA", startOffset + 4 * 14, "", sizeStr(4), optional_headers.DataDirectory[7].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[7].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Architecture Directory Size", startOffset + 4 * 15, "", sizeStr(4), optional_headers.DataDirectory[7].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Reserved", startOffset + 4 * 16, "", sizeStr(4), optional_headers.DataDirectory[8].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[8].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Reserved", startOffset + 4 * 17, "", sizeStr(4), optional_headers.DataDirectory[8].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "TLS Directory RVA", startOffset + 4 * 18, "", sizeStr(4), optional_headers.DataDirectory[9].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[9].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "TLS Directory Size", startOffset + 4 * 19, "", sizeStr(4), optional_headers.DataDirectory[9].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Configuration Directory RVA", startOffset + 4 * 20, "", sizeStr(4), optional_headers.DataDirectory[10].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[10].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Configuration Directory Size", startOffset + 4 * 21, "", sizeStr(4), optional_headers.DataDirectory[10].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Bound Import Directory RVA", startOffset + 4 * 22, "", sizeStr(4), optional_headers.DataDirectory[11].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[11].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Bound Import Directory Size", startOffset + 4 * 23, "", sizeStr(4), optional_headers.DataDirectory[11].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Import Address Table Directory RVA", startOffset + 4 * 24, "", sizeStr(4), optional_headers.DataDirectory[12].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[12].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Import Address Table Directory Size", startOffset + 4 * 25, "", sizeStr(4), optional_headers.DataDirectory[12].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Delay Import Directory RVA", startOffset + 4 * 26, "", sizeStr(4), optional_headers.DataDirectory[13].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[13].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Delay Import Directory Size", startOffset + 4 * 27, "", sizeStr(4), optional_headers.DataDirectory[13].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", ".NET MetaData Directory RVA", startOffset + 4 * 28, "", sizeStr(4), optional_headers.DataDirectory[14].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[14].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", ".NET MetaData Directory Size", startOffset + 4 * 29, "", sizeStr(4), optional_headers.DataDirectory[14].Size);
}

void dataDirectoriesDisplay32(IMAGE_NT_HEADERS32 nt_headers, IMAGE_SECTION_HEADER *section_headers)
{
    int startOffset = dos_header.e_lfanew + 4 + 20 + IMAGE_SIZEOF_NT_OPTIONAL32_HEADER - IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY);
    IMAGE_OPTIONAL_HEADER32 optional_headers = nt_headers.OptionalHeader;
    printf("\n-----Data Directories-----\n");
    printf("\033[1;31m%-40s %-10s %-10s %-10s %s\033[0m\n", "Member", "Offset", "Size", "Value", "Section");
    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Export Directory RVA", startOffset, "", sizeStr(4), optional_headers.DataDirectory[0].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[0].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Export Directory Size", startOffset + 4 * 1, "", sizeStr(4), optional_headers.DataDirectory[0].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Import Directory RVA", startOffset + 4 * 2, "", sizeStr(4), optional_headers.DataDirectory[1].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[1].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Import Directory Size", startOffset + 4 * 3, "", sizeStr(4), optional_headers.DataDirectory[1].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Resource Directory RVA", startOffset + 4 * 4, "", sizeStr(4), optional_headers.DataDirectory[2].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[2].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Resource Directory Size", startOffset + 4 * 5, "", sizeStr(4), optional_headers.DataDirectory[2].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Exception Directory RVA", startOffset + 4 * 6, "", sizeStr(4), optional_headers.DataDirectory[3].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[3].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Exception Directory Size", startOffset + 4 * 7, "", sizeStr(4), optional_headers.DataDirectory[3].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Security Directory RVA", startOffset + 4 * 8, "", sizeStr(4), optional_headers.DataDirectory[4].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[4].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Security Directory Size", startOffset + 4 * 9, "", sizeStr(4), optional_headers.DataDirectory[4].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Relocation Directory RVA", startOffset + 4 * 10, "", sizeStr(4), optional_headers.DataDirectory[5].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[5].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Relocation Directory Size", startOffset + 4 * 11, "", sizeStr(4), optional_headers.DataDirectory[5].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Debug Directory RVA", startOffset + 4 * 12, "", sizeStr(4), optional_headers.DataDirectory[6].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[6].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Debug Directory Size", startOffset + 4 * 13, "", sizeStr(4), optional_headers.DataDirectory[6].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Architecture Directory RVA", startOffset + 4 * 14, "", sizeStr(4), optional_headers.DataDirectory[7].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[7].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Architecture Directory Size", startOffset + 4 * 15, "", sizeStr(4), optional_headers.DataDirectory[7].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Reserved", startOffset + 4 * 16, "", sizeStr(4), optional_headers.DataDirectory[8].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[8].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Reserved", startOffset + 4 * 17, "", sizeStr(4), optional_headers.DataDirectory[8].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "TLS Directory RVA", startOffset + 4 * 18, "", sizeStr(4), optional_headers.DataDirectory[9].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[9].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "TLS Directory Size", startOffset + 4 * 19, "", sizeStr(4), optional_headers.DataDirectory[9].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Configuration Directory RVA", startOffset + 4 * 20, "", sizeStr(4), optional_headers.DataDirectory[10].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[10].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Configuration Directory Size", startOffset + 4 * 21, "", sizeStr(4), optional_headers.DataDirectory[10].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Bound Import Directory RVA", startOffset + 4 * 22, "", sizeStr(4), optional_headers.DataDirectory[11].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[11].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Bound Import Directory Size", startOffset + 4 * 23, "", sizeStr(4), optional_headers.DataDirectory[11].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Import Address Table Directory RVA", startOffset + 4 * 24, "", sizeStr(4), optional_headers.DataDirectory[12].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[12].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Import Address Table Directory Size", startOffset + 4 * 25, "", sizeStr(4), optional_headers.DataDirectory[12].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", "Delay Import Directory RVA", startOffset + 4 * 26, "", sizeStr(4), optional_headers.DataDirectory[13].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[13].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", "Delay Import Directory Size", startOffset + 4 * 27, "", sizeStr(4), optional_headers.DataDirectory[13].Size);

    printf("%-40s %08X%-2s %-10s %08X%-2s %s\n", ".NET MetaData Directory RVA", startOffset + 4 * 28, "", sizeStr(4), optional_headers.DataDirectory[14].VirtualAddress, "", sectionOfRva(section_headers, optional_headers.DataDirectory[14].VirtualAddress));
    printf("%-40s %08X%-2s %-10s %08X\n", ".NET MetaData Directory Size", startOffset + 4 * 29, "", sizeStr(4), optional_headers.DataDirectory[14].Size);
}

void sectionHeadersDisplay(IMAGE_SECTION_HEADER *section_headers)
{
    printf("\n-----Section Headers-----\n");
    printf("\033[1;31m%-10s %-15s %-20s %-10s %-15s %-15s %-15s %-20s %-20s %-20s\033[0m\n", "Name", "Virtual Size", "Virtual Address", "Raw Size", "Raw Address", "Reloc Address", "Linenumbers", "Relocations Number", "Linenumbers Number", "Characteristics");
    for (int i = 0; i < file_header.NumberOfSections; i++)
    {
        printf("%-10s ", section_headers[i].Name);
        printf("%08X%-7s ", section_headers[i].Misc.VirtualSize, "");
        printf("%08X%-12s ", section_headers[i].VirtualAddress, "");
        printf("%08X%-2s ", section_headers[i].SizeOfRawData, "");
        printf("%08X%-7s ", section_headers[i].PointerToRawData, "");
        printf("%08X%-7s ", section_headers[i].PointerToRelocations, "");
        printf("%08X%-7s ", section_headers[i].PointerToLinenumbers, "");
        printf("%08X%-12s ", section_headers[i].NumberOfRelocations, "");
        printf("%08X%-12s ", section_headers[i].NumberOfLinenumbers, "");
        printf("%08X%-12s\n", section_headers[i].Characteristics, "");
    }
}

void importDirectoryDisplay(FILE *file, IMAGE_SECTION_HEADER *section_header, int importDirectoryRva, int magic)
{
    DWORD import_file_offset = convertRvaToOffset(section_header, importDirectoryRva);
    fseek(file, import_file_offset, SEEK_SET);
    IMAGE_IMPORT_DESCRIPTOR import_descriptor;

    printf("\n-----Import Directory-----\n");
    printf("\033[1;31m%-60s %-10s %-15s %-15s %-10s %-10s\033[0m\n", "Module Name", "OFTs", "TimeDateStamp", "ForwarderChain", "NameRVA", "FTs (IAT)");

    while (1)
    {
        fread(&import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);

        if (import_descriptor.Name == 0)
            break;

        DWORD name_offset = convertRvaToOffset(section_header, import_descriptor.Name);
        fseek(file, name_offset, SEEK_SET);

        char dll_name[256];
        fgets(dll_name, sizeof(dll_name), file);
        printf("%-60s ", dll_name);
        printf("%08lX%-2s ", import_descriptor.OriginalFirstThunk, "");
        printf("%08lX%-7s ", import_descriptor.TimeDateStamp, "");
        printf("%08lX%-7s ", import_descriptor.ForwarderChain, "");
        printf("%08lX%-2s ", import_descriptor.Name, "");
        printf("%08lX\n", import_descriptor.FirstThunk);

        fseek(file, import_file_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR), SEEK_SET);
    }

    printf("\nPress any key to continue...");
    char c = getchar();

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        importFunctionsDisplay32(file, section_header, importDirectoryRva);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        importFunctionsDisplay64(file, section_header, importDirectoryRva);
    }
}

void importFunctionsDisplay64(FILE *file, IMAGE_SECTION_HEADER *section_header, int importDirectoryRva)
{
    DWORD import_file_offset = convertRvaToOffset(section_header, importDirectoryRva);
    fseek(file, import_file_offset, SEEK_SET);
    IMAGE_IMPORT_DESCRIPTOR import_descriptor;

    IMAGE_THUNK_DATA64 ordinar_first_thunk_data;
    IMAGE_THUNK_DATA64 first_thunk_data;

    unsigned long long total;

    while (1)
    {
        fread(&import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);

        if (import_descriptor.Name == 0)
            break;

        // Read Import DLL Name => dll_name
        DWORD import_name_offset = convertRvaToOffset(section_header, import_descriptor.Name);
        fseek(file, import_name_offset, SEEK_SET);
        char dll_name[256];
        fgets(dll_name, sizeof(dll_name), file);

        // ordinal first thunk table
        DWORD ofts_rva = import_descriptor.OriginalFirstThunk;
        DWORD ofts_offset = convertRvaToOffset(section_header, ofts_rva);

        // first thunk table
        DWORD fts_rva = import_descriptor.FirstThunk;
        DWORD fts_offset = convertRvaToOffset(section_header, fts_rva);

        printf("\n-----Functions In \033[1;32m%s\033[0m-----\n", dll_name);
        printf("\033[1;31m%-20s %-20s %-10s %s\033[0m\n", "OFTs", "FTs (IAT)", "Hint", "Name");

        total = 0;
        while (1)
        {
            // Read ordinal first thunk
            fseek(file, ofts_offset, SEEK_SET);
            fread(&ordinar_first_thunk_data, sizeof(IMAGE_THUNK_DATA64), 1, file);

            if (ordinar_first_thunk_data.u1.AddressOfData == 0)
            {
                break;
            }
            // Display ordinal first thunk
            printf("%016X%-4s ", ordinar_first_thunk_data.u1.AddressOfData, "");

            // Read first thunk
            fseek(file, fts_offset, SEEK_SET);
            fread(&first_thunk_data, sizeof(IMAGE_THUNK_DATA64), 1, file);

            // Display first thunk
            printf("%016X%-4s ", first_thunk_data.u1.AddressOfData, "");

            DWORD name_function_offset = convertRvaToOffset(section_header, ordinar_first_thunk_data.u1.AddressOfData);

            IMAGE_IMPORT_BY_NAME import_by_name;
            fseek(file, name_function_offset, SEEK_SET);
            fread(&import_by_name.Hint, sizeof(import_by_name.Hint), 1, file);
            printf("%04X%-6s ", import_by_name.Hint, "");

            char c;
            fseek(file, name_function_offset + 2, SEEK_SET);
            while (fread(&c, sizeof(char), 1, file) && c != 0x0)
            {
                printf("%c", c);
            }
            printf("\n");

            ofts_offset = convertRvaToOffset(section_header, ofts_rva += sizeof(IMAGE_THUNK_DATA64));
            fts_offset = convertRvaToOffset(section_header, fts_rva += sizeof(IMAGE_THUNK_DATA64));
            total += 1;
        }
        printf("Total Functions: %lld\n", total);

        printf("\nPress any key to continue...");
        char c = getchar();

        fseek(file, import_file_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR), SEEK_SET);
    }
}

void importFunctionsDisplay32(FILE *file, IMAGE_SECTION_HEADER *section_header, int importDirectoryRva)
{
    DWORD import_file_offset = convertRvaToOffset(section_header, importDirectoryRva);
    fseek(file, import_file_offset, SEEK_SET);
    IMAGE_IMPORT_DESCRIPTOR import_descriptor;

    IMAGE_THUNK_DATA32 ordinar_first_thunk_data;
    IMAGE_THUNK_DATA32 first_thunk_data;

    unsigned long long total;

    while (1)
    {
        fread(&import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);

        if (import_descriptor.Name == 0)
            break;

        // Read Import DLL Name => dll_name
        DWORD import_name_offset = convertRvaToOffset(section_header, import_descriptor.Name);
        fseek(file, import_name_offset, SEEK_SET);
        char dll_name[256];
        fgets(dll_name, sizeof(dll_name), file);

        // ordinal first thunk table
        DWORD ofts_rva = import_descriptor.OriginalFirstThunk;
        DWORD ofts_offset = convertRvaToOffset(section_header, ofts_rva);

        // first thunk table
        DWORD fts_rva = import_descriptor.FirstThunk;
        DWORD fts_offset = convertRvaToOffset(section_header, fts_rva);

        printf("\n-----Functions In \033[1;32m%s\033[0m-----\n", dll_name);
        printf("\033[1;31m%-20s %-20s %-10s %s\033[0m\n", "OFTs", "FTs (IAT)", "Hint", "Name");

        total = 0;
        while (1)
        {
            // Read ordinal first thunk
            fseek(file, ofts_offset, SEEK_SET);
            fread(&ordinar_first_thunk_data, sizeof(IMAGE_THUNK_DATA32), 1, file);

            if (ordinar_first_thunk_data.u1.AddressOfData == 0)
            {
                break;
            }
            // Display ordinal first thunk
            printf("%08X%-12s ", ordinar_first_thunk_data.u1.AddressOfData, "");

            // Read first thunk
            fseek(file, fts_offset, SEEK_SET);
            fread(&first_thunk_data, sizeof(IMAGE_THUNK_DATA32), 1, file);

            // Display first thunk
            printf("%08X%-12s ", first_thunk_data.u1.AddressOfData, "");

            DWORD name_function_offset = convertRvaToOffset(section_header, ordinar_first_thunk_data.u1.AddressOfData);

            IMAGE_IMPORT_BY_NAME import_by_name;
            fseek(file, name_function_offset, SEEK_SET);
            fread(&import_by_name.Hint, sizeof(import_by_name.Hint), 1, file);
            printf("%04X%-6s ", import_by_name.Hint, "");

            char c;
            fseek(file, name_function_offset + 2, SEEK_SET);
            while (fread(&c, sizeof(char), 1, file) && c != 0x0)
            {
                printf("%c", c);
            }
            printf("\n");

            ofts_offset = convertRvaToOffset(section_header, ofts_rva += sizeof(IMAGE_THUNK_DATA32));
            fts_offset = convertRvaToOffset(section_header, fts_rva += sizeof(IMAGE_THUNK_DATA32));
            total += 1;
        }
        printf("Total Functions: %lld\n", total);

        printf("\nPress any key to continue...");
        char c = getchar();

        fseek(file, import_file_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR), SEEK_SET);
    }
}

DWORD convertRvaToOffset(IMAGE_SECTION_HEADER *section_headers, QWORD rva)
{
    DWORD offset;
    QWORD lowerLimit;
    QWORD upperLimit;
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        lowerLimit = section_headers[i].VirtualAddress;
        if (section_headers[i].Misc.VirtualSize >= section_headers[i].SizeOfRawData)
        {
            upperLimit = lowerLimit + section_headers[i].Misc.VirtualSize;
        }
        else
        {
            upperLimit = lowerLimit + section_headers[i].Misc.VirtualSize + (section_headers[i].SizeOfRawData - section_headers[i].Misc.VirtualSize);
        }

        if (rva >= lowerLimit && rva < upperLimit && rva != 0)
        {
            offset = rva - (section_headers[i].VirtualAddress - section_headers[i].PointerToRawData);
            break;
        }
    }
    return offset;
}

char *sizeStr(int n)
{
    char *str;
    switch (n)
    {
    case 2:
        str = "Word";
        break;
    case 4:
        str = "Dword";
        break;
    case 8:
        str = "Qword";
        break;
    default:
        str = "Byte";
        break;
    }
    return str;
}

char *machineTypes(int n)
{
    char *str;
    switch (n)
    {
    case IMAGE_FILE_MACHINE_UNKNOWN:
        str = "Unknown Value";
        break;
    case IMAGE_FILE_MACHINE_I386:
        str = "Intel 386";
        break;
    case IMAGE_FILE_MACHINE_R3000:
        str = "R3000 - MIPS";
        break;
    case IMAGE_FILE_MACHINE_R4000:
        str = "R4000 - MIPS";
        break;
    case IMAGE_FILE_MACHINE_R10000:
        str = "R10000 - MIPS";
        break;
    case IMAGE_FILE_MACHINE_WCEMIPSV2:
        str = "MIPS WCE v2";
        break;
    case IMAGE_FILE_MACHINE_ALPHA:
        str = "Alpha_AXP";
        break;
    case IMAGE_FILE_MACHINE_SH3:
        str = "SH3";
        break;
    case IMAGE_FILE_MACHINE_SH3DSP:
        str = "SH3DSP";
        break;
    case IMAGE_FILE_MACHINE_SH3E:
        str = "SH3E";
        break;
    case IMAGE_FILE_MACHINE_SH4:
        str = "SH4";
        break;
    case IMAGE_FILE_MACHINE_SH5:
        str = "SH5";
        break;
    case IMAGE_FILE_MACHINE_ARM:
        str = "ARM";
        break;
    case IMAGE_FILE_MACHINE_THUMB:
        str = "ARM Thumb";
        break;
    case IMAGE_FILE_MACHINE_AM33:
        str = "ARM AM33";
        break;
    case IMAGE_FILE_MACHINE_POWERPC:
        str = "IBM PowerPC";
        break;
    case IMAGE_FILE_MACHINE_POWERPCFP:
        str = "IBM PowerPC FP";
        break;
    case IMAGE_FILE_MACHINE_IA64:
        str = "Intel 64";
        break;
    case IMAGE_FILE_MACHINE_MIPS16:
        str = "MIPS16";
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU:
        str = "MIPSFPU";
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU16:
        str = "MIPSFPU16";
        break;
    case IMAGE_FILE_MACHINE_ALPHA64:
        str = "ALPHA64";
        break;
    case IMAGE_FILE_MACHINE_TRICORE:
        str = "Infineon TriCore";
        break;
    case IMAGE_FILE_MACHINE_CEF:
        str = "Infineon CEF";
        break;
    case IMAGE_FILE_MACHINE_EBC:
        str = "EFI Byte Code";
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        str = "AMD64 (K8)";
        break;
    case IMAGE_FILE_MACHINE_M32R:
        str = "M32R";
        break;
    case IMAGE_FILE_MACHINE_CEE:
        str = "CEE";
        break;
    default:
        str = "";
        break;
    }
    return str;
}

char *magicNumber(int n)
{
    char *str;
    switch (n)
    {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        str = "PE32";
        break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        str = "PE64";
        break;
    case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
        str = "ROM";
        break;
    default:
        str = "";
        break;
    }
    return str;
}
