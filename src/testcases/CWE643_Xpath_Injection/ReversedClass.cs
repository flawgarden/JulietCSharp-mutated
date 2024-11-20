
namespace HelperOperators;

public class SAIReversed : StaticAbstractInterface<SAIReversed>
{
    public static SAIReversed GetEmptyT() => new();

    public static SAIReversed ATProperty { get; set; }

    public static SAIReversed VGetInner(bool b) => b ? SAIReversed.GetEmptyT() : SAIReversed.ATProperty;

    public string value;

    public SAIReversed() : this("") {}

    public SAIReversed(string s)
    {
        value = "";
    }
}