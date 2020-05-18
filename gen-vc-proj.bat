cmake ^
    -S . ^
    -B .build ^
    -G "Visual Studio 16 2019" ^
    -A Win32 ^
    -DCMAKE_INSTALL_PREFIX=./pacakge ^
    -DBUILD_SHELLCODE_GEN=TRUE ^
    -DBUILD_MMLOADER_DEMO=TRUE