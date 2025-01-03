
namespace AbstractHelpers;

public class ClassInverted : AClass
{
    public override string OverriddenPositive(string input)
    {
        return "";
    }
    public override string OverriddenNegative(string input)
    {
        return input;
    }
    public new string NonOverriddenPositive(string input)
    {
        return "";
    }
    public new string NonOverriddenNegative(string input)
    {
        return input;
    }
    public override string APositive(string input)
    {
        return "";
    }
    public override string ANegative(string input)
    {
        return input;
    }
}
