
namespace AbstractHelpers;

public class SealedMemberClass : AClass
{
    public sealed override string APositive(string input)
    {
        return input;
    }
    public sealed override string ANegative(string input)
    {
        return "";
    }
}
