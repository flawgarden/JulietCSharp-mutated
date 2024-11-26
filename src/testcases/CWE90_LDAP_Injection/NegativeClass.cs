
namespace HelperOperators;

public class SAINegative : StaticAbstractInterface<SAINegative>
{
    public static SAINegative GetEmptyT() => new();

    private static SAINegative _property = new();

    public static SAINegative ATProperty
    {
        get => _property;
        set => _property = new();
    }

    public static SAINegative VGetInner(bool b) => _property;

    public string value;

    public SAINegative() : this("") {}

    public SAINegative(string s)
    {
        value = "";
    }
}
