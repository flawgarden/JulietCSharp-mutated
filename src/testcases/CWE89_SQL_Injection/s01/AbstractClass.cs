
namespace AbstractHelpers;

public abstract class AClass
{
    public virtual string OverriddenPositive(string input)
    {
        return input;
    }
    public virtual string OverriddenNegative(string input)
    {
        return "";
    }
    public virtual string NonOverriddenPositive(string input)
    {
        return input;
    }
    public virtual string NonOverriddenNegative(string input)
    {
        return "";
    }
    public abstract string APositive(string input);
    public abstract string ANegative(string input);
}
