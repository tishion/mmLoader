# mmLoader

Load memory module.

mmLoader is used for loaing dll module from memory directly. It can bypass the windows system PE loader load and load module into process address sapce. Also it will process all the import tables and reloaction table.

You can just include the mmLoader\mmLoader folder as source file in your projects, or just copy files in that folder to your projects.

Threre are two way to use it.

1. Use the source code:
   See also LoaderDemoExe\LoaderDemoExe.cpp

2. Use the shell code:
   See also mmLoaderShellCodeDemo\mmLoaderShellCodeDemo.cpp
