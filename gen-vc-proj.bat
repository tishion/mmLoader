cmake ^
    -S . ^
    -B .build ^
    -A Win32 ^
    -DCMAKE_INSTALL_PREFIX=./pacakge ^
    -DBUILD_SHELLCODE_GEN=TRUE ^
    -DBUILD_MMLOADER_DEMO=TRUE
