
namespace HelperStructs;

public ref struct RefReadonlyFieldStruct
{
    public string str;
    public ref string strRef;
    public readonly string strRd;
    public ref readonly string strRefRd;
    public readonly ref string strRdRef;

    public RefReadonlyFieldStruct(ref string s)
    {
        str = s;
        strRef = ref s;
        strRd = s;
        strRefRd = ref s;
        strRdRef = ref s;
    }
}
