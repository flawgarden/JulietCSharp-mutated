
namespace HelperStructs;
using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
public struct SerializableStruct
{
    public string str;
    public int count;

    public SerializableStruct(string s, int n)
    {
        str = s;
        count = n;
    }
}