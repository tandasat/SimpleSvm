SimpleSvm
==========

Introduction
-------------

SimpleSvm is a minimalistic educational hypervisor for Windows on AMD processors.
It aims to provide small and explanational code to use Secure Virtual Machine (SVM),
the AMD version of Intel VT-x, with Nested Page Tables (NPT) from a windows driver.

SimpleSvm is inspired by SimpleVisor, an Intel x64/EM64T VT-x specific hypervisor
for Windows, written by Alex Ionescu (@aionescu).


Supported Platforms
----------------------
- Windows 10 x64 and Windows 7 x64
- AMD Processors with SVM and NPT support


Resources
-------------------
- AMD64 Architecture Programmer’s Manual Volume 2 and 3
  - http://developer.amd.com/resources/developer-guides-manuals/

- SimpleVisor
  - http://ionescu007.github.io/SimpleVisor/

- HelloAmdHvPkg
  - https://github.com/tandasat/HelloAmdHvPkg
