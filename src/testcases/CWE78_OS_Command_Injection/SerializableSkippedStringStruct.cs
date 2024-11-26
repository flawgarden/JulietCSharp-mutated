
namespace HelperStructs;
using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
public struct SerializableSkippedStringStruct
{
    public int count;
    [NonSerialized]
    public string str;

    public SerializableSkippedStringStruct(string s, int n)
    {
        str = s;
        count = n;
    }
}
