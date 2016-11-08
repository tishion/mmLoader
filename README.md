# mmLoader

Load memory module.

**Reformed! Provide static libray build and easy way to use shell code.**

mmLoader is used for loaing dll module from memory directly. It can bypass the windows system PE loader load and load module into process address sapce. Also it will process all the import tables and reloaction table.

You can just include the mmLoader\mmLoader folder as source file in your projects, or just copy files in that folder to your projects.

There are three ways to use it.

1. Use the source code:
   Just copy the source file inyo your projects.

2. Use the static library
    Build the projects and collect the static library file, then add reference in your projects.

3. Use the shell code
   Build project mmLoader-shellcode-generator then run it, you will get the generated header file, put the header file in your project and enjoy it!

