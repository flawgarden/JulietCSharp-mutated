
namespace AbstractHelpers;

public class ClassInherited : AClass
{
    public override string APositive(string input)
    {
        return input;
    }
    public override string ANegative(string input)
    {
        return "";
    }
}
