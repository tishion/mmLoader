cmake ^
    -S . ^
    -B .build/win32 ^
    -A Win32 ^
    -DCMAKE_INSTALL_PREFIX=./pacakge ^
    -DBUILD_SHELLCODE_GEN=TRUE ^
    -DBUILD_MMLOADER_DEMO=TRUE
