
namespace HelperStructs;

public readonly struct ReadonlyStruct
{
    public readonly string str;
    public readonly int count;

    public ReadonlyStruct(string s, int n)
    {
        str = s;
        count = n;
    }
}