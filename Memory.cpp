#include "Memory.h"


#pragma region constructors
Memory::Memory(const std::string& process_name) {

    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    m_min_proc_address = (uintptr_t)sys_info.lpMinimumApplicationAddress;
    m_max_proc_address = (uintptr_t)sys_info.lpMaximumApplicationAddress;

    m_process_id = m_get_process_id(process_name);
    m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, m_process_id);
}

Memory::Memory(DWORD process_id) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    m_min_proc_address = (uintptr_t)sys_info.lpMinimumApplicationAddress;
    m_max_proc_address = (uintptr_t)sys_info.lpMaximumApplicationAddress;

    m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, m_process_id);
}

Memory::Memory(HWND window) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    m_min_proc_address = (uintptr_t)sys_info.lpMinimumApplicationAddress;
    m_max_proc_address = (uintptr_t)sys_info.lpMaximumApplicationAddress;

    m_process_id = m_get_process_id(window);
    m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, m_process_id);
}

Memory::Memory() {
    m_process_handle = 0;
    m_process_id = 0;
    m_min_proc_address = 0, m_max_proc_address = 0;
}

#pragma endregion

#pragma region get methods
HANDLE Memory::get_handle() {
    return m_process_handle;
}


DWORD Memory::get_pid() {
    return m_process_id;
}
#pragma endregion

#pragma region get proc info
DWORD Memory::m_get_process_id(const std::string& process_name) {

    PROCESSENTRY32 pt;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pt.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hsnap, &pt)) {
        do {
            if (!lstrcmpi(pt.szExeFile, process_name.c_str())) {
                CloseHandle(hsnap);
                return pt.th32ProcessID;
            }
        } while (Process32Next(hsnap, &pt));
    }
    CloseHandle(hsnap);
    return 0;

}

DWORD Memory::m_get_process_id(HWND window) {
    DWORD pid;
    GetWindowThreadProcessId(window, &pid);
    return pid;
}



address Memory::get_module_address(const std::string& module_name) {
    MODULEENTRY32 entry = { };
    entry.dwSize = sizeof(::MODULEENTRY32);

    const auto snapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_process_id);

    uintptr_t result = 0;

    while (::Module32Next(snapShot, &entry))
    {
        if (!module_name.compare(entry.szModule))
        {
            result = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            break;
        }
    }

    if (snapShot)
        CloseHandle(snapShot);

    return result;
}
#pragma endregion

#pragma region scanners
std::vector<address> Memory::pattern_scanner(const std::vector<unsigned char>& pattern) {

    std::vector<uintptr_t > output;

    MEMORY_BASIC_INFORMATION mbi;

    for (address base_address = 0; VirtualQueryEx(m_process_handle, (LPCVOID)base_address, &mbi, sizeof(mbi)); base_address += mbi.RegionSize) {

        if ((mbi.State & MEM_COMMIT) && (mbi.Protect & PAGE_EXECUTE_READWRITE) && base_address != 0) {

            std::vector<unsigned char> buffer(mbi.RegionSize);

            if (ReadProcessMemory(m_process_handle, (LPCVOID)base_address, &buffer[0], buffer.size(), nullptr)) {

                for (size_t i = 0; i < buffer.size(); i++) {

                    bool found = true;

                    for (size_t x = 0; x < pattern.size(); ++x) {

                        if (pattern[x] != buffer[i + x]) {

                            found = false;
                            break;

                        }

                    }

                    if (found) output.push_back(base_address + i);

                }
            }
        }
    }

    return output;
}


template <class T>
std::vector<address> Memory::scan_for_value(T value) {
    std::vector<uintptr_t > output;

    MEMORY_BASIC_INFORMATION mbi;

    for (address base_address = 0; VirtualQueryEx(m_process_handle, (LPCVOID)base_address, &mbi, sizeof(mbi)); base_address += mbi.RegionSize) {

        if ((mbi.State & MEM_COMMIT) && (mbi.Protect & PAGE_EXECUTE_READWRITE) && base_address != 0) {

            std::vector<T> buffer(mbi.RegionSize);

            if (ReadProcessMemory(m_process_handle, (LPCVOID)base_address, &buffer[0], buffer.size(), nullptr)) {

                for (size_t i = 0; i < buffer.size(); i++) {

                    if (value == buffer[i]) output.push_back(base_address + i);

                }
            }
        }
    }

    return output;
}

std::vector<size_t> Memory::m_get_indexes_of_substring(std::string string, std::string substring) {
    std::vector<size_t> indexes = {};
    size_t index = 0;
    while (true) {
        size_t x = string.find(substring, index);
        if (x == std::string::npos) break;
        indexes.push_back(x);
        index = x + substring.length();
    }
    return indexes;
}



size_t Memory::delete_strings(const std::vector<std::string>& strings_to_remove) {
    size_t removed_strings_count = 0;

    MEMORY_BASIC_INFORMATION mbi;

    for (address base_address = 0; VirtualQueryEx(m_process_handle, (LPCVOID)base_address, &mbi, sizeof(mbi)); base_address += mbi.RegionSize) {

        if ((mbi.State & MEM_COMMIT) && (mbi.Protect & PAGE_EXECUTE_READWRITE) && base_address != 0) {

            std::string buffer(mbi.RegionSize, 0);

            if (ReadProcessMemory(m_process_handle, (void*)base_address, &buffer[0], mbi.RegionSize, 0)) {

                for (const std::string& string_to_remove : strings_to_remove) {

                    std::string replace(string_to_remove.size(), 0);
                    std::vector<size_t> indexes = this->m_get_indexes_of_substring(buffer, string_to_remove);

                    for (const size_t index : indexes) {
                        if (WriteProcessMemory(m_process_handle, (void*)(base_address + index), &replace, sizeof(replace), 0)) removed_strings_count++;

                    }
                }
            }

        }
    }
    return removed_strings_count;
}
#pragma endregion


bool Memory::set_debug_privilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return true;
    }
    return false;
}

Memory::~Memory() {
    if (m_process_handle) CloseHandle(m_process_handle);
}
