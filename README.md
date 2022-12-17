# Memory

A simple class containing useful methods to make memory hacking easier and faster.

## Docs

### Constructors
- **Memory(const std::string& process_name)**
- **Memory(DWORD process_id)**
- **Memory(HWND window)**
- **Memory()**

### Methods
- **address get_module_address(const std::string& module_name):**    
Returns the address of the module specified.

- **HANDLE get_handle():**   
Returns a PROCESS_ALL_ACCESS handle to the targeted process.

- **DWORD get_pid():**   
Returns the id of the targeted process.

- **T read(address address):**    
Reads the targeted process memory at the specified address.

- **void write(address address, T value):**    
Writes the value parameter at the the targeted process address specified.

- **scan_for_value(T value):**     
Scans the whole targeted process and returns a vector containing the addresses of all the instances of the specified value.

- **pattern_scanner(pattern):**    
Scans the whole targeted process and returns a vector containing the addresses of all the instances of the specified pattern. The pattern is a reference to a vector of unsigned char.

- **size_t delete_strings(strings_to_remove):**   
Scans the whole targeted process and removes all the strings specified. Returns the count of how many strings the function removed from the targeted process. The strings_to_remove parameter is a reference to a vector of std::string.

- **bool set_debug_privilege():**    
Sets SeDebugPrivilege.
