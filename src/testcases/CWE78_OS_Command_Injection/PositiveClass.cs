
namespace HelperOperators;

public class SAIPositive : StaticAbstractInterface<SAIPositive>
{
    public static SAIPositive GetEmptyT() => new();

    public static SAIPositive ATProperty { get; set; } = new();

    public string value;

    public SAIPositive() : this("") {}

    public SAIPositive(string s)
    {
        value = s;
    }
}
