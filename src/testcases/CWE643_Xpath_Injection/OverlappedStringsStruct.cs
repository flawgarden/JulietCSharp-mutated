
namespace HelperStructs;
using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
[StructLayout(LayoutKind.Explicit)]
public struct OverlappedStringsStruct
{
    [FieldOffset(0)]
    public string str1;
    [FieldOffset(0)]
    public string str2;
}
