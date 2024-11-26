
namespace PartialHelpers;

public partial class PartialClass
{
    public string StrOne;

    public PartialClass(string one, string two)
    {
        StrOne = one;
        StrTwo = two;
    }

    public void ReassignStrTwo(string str)
    {
        StrTwo = str;
    }

    public partial void ReassignStrOne(string str);
}
