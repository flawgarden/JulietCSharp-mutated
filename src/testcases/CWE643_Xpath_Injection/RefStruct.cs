
namespace HelperStructs;

public ref struct RefStruct
{
    public string str;
    public int count;

    public RefStruct(string s, int n)
    {
        str = s;
        count = n;
    }
}