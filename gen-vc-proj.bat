cmake ^
    -S . ^
    -B .build ^
    -G "Visual Studio 16 2019" ^
    -A Win32 ^
    -DCMAKE_SYSTEM_VERSION=10.0.18362.0 ^
    -DCMAKE_INSTALL_PREFIX=./pacakge ^
    -DBUILD_SHELLCODE_GEN=TRUE ^
    -DBUILD_MMLOADER_DEMO=TRUE
