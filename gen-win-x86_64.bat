cmake ^
    -S . ^
    -B .build/win64 ^
    -A x64 ^
    -DCMAKE_INSTALL_PREFIX=./pacakge ^
    -DBUILD_SHELLCODE_GEN=TRUE ^
    -DBUILD_MMLOADER_DEMO=TRUE
