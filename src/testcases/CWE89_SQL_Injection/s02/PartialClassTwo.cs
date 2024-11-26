
namespace PartialHelpers;

public partial class PartialClass
{
    public string StrTwo;

    public partial void ReassignStrOne(string str)
    {
        StrOne = str;
    }
}
