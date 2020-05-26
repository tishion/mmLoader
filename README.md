## mmLoader 

mmLoader is a library used for loading DLL modules from memory directly. Also, it will bypass the Windows PE loader with processing the import/export table correctly.

| triplets  | status  |
|---|---|
| x86-windows-static | [![Build status](https://dev.azure.com/sheentian/GitHub-CI/_apis/build/status/mmLoader/mmloader-x86-windows-static)](https://dev.azure.com/sheentian/GitHub-CI/_build/latest?definitionId=11) |
| x64-windows-static | [![Build status](https://dev.azure.com/sheentian/GitHub-CI/_apis/build/status/mmLoader/mmloader-x64-windows-static)](https://dev.azure.com/sheentian/GitHub-CI/_build/latest?definitionId=25) |


[DOC](http://tishion.github.io/mmLoader/) | [CI&CD](https://dev.azure.com/sheentian/GitHub-CI)

The CI & CD system has been moved to Azure DevOps and mmLoader will not publish more nugget packages.


### vcpkg support
mmloader is available on vcpkg now, just install it by the commmand:
> vcpkg install mmloader:x86-windows-static

> vcpkg install mmloader:x64-windows-static

if you want to use mmloader in shellcod mode, you need to install it with feature shellcode:
> vcpkg install mmloader[shellcode]:x86-windows-static

> vcpkg install mmloader[shellcode]:x64-windows-static

### build from source

The build system has been switched to CMake, you can generate and build the project with the following commands:
#### generate the project files
> cmake -S . -B .build -G "Visual Studio 16 2019" -A Win32 -DBUILD_SHELLCODE_GEN=TRUE -DBUILD_MMLOADER_DEMO=TRUE

> -S .: the source tree root folder   
> -B .build: the build folder .build  
> -G "Visual Studio xx xxxx": generate the solution file for VS  
> -A : target architecture, support Win32 & x64 only  
> -DBUILD_SHELLCODE_GEN=TRUE: enable shellcode generator  
> -DBUILD_MMLOADER_DEMO=TRUE: enable demo projects  

#### build the projects
> cmake --build .build


## How to use

1. Use mmLoader source code:
   - Just include the source files in your projects.

2. Use mmLoader static library
   - Build the projects and collect the static library file, then add reference to it in your projects.

4. Use mmLoader shell code
   - Build project mmLoader-shellcode-generator then run it, collect the generated header file. 
   - Include the header file in your project

## FAQ
Q: Why no dynamic version? 

A: Compiling mmLoader as separated dynamic module is not recommended for some obvious reasons.
