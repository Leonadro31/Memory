#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>

typedef uintptr_t address;

class Memory {
private:
    HANDLE m_process_handle;
    DWORD  m_process_id;

    address m_min_proc_address, m_max_proc_address;

    DWORD m_get_process_id(const std::string& process_name);
    DWORD m_get_process_id(HWND window);
    std::vector<size_t> m_get_indexes_of_substring(std::string string, std::string substring);

public:

    Memory(const std::string& process_name);
    Memory(DWORD process_id);
    Memory(HWND window);
    Memory();
    ~Memory();


    address get_module_address(const std::string& module_name);

    HANDLE get_handle();
    DWORD get_pid();

    template <class T>
    std::vector<address> scan_for_value(T value);

    template <class T> T read(address address)
    {
        if (address > m_max_proc_address || address < m_min_proc_address) return NULL;

        T value;
        ReadProcessMemory(this->m_process_handle, reinterpret_cast<void*>(address), &value, sizeof(T), NULL);
        return value;
    }

    template <class T>
    void write(address address, T value)
    {
        if (address > m_max_proc_address || address < m_min_proc_address) return;

        WriteProcessMemory(this->m_process_handle, reinterpret_cast<void*>(address), &value, sizeof(T), NULL);

    }

    std::vector<address> pattern_scanner(const std::vector<unsigned char>& pattern);

    size_t delete_strings(const std::vector<std::string>& strings_to_remove);

    bool set_debug_privilege();

};
