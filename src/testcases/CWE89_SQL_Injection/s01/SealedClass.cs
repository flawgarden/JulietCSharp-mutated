
namespace HelperFields;

public sealed class SealedStringHolder
{
    public string value;

    public SealedStringHolder() : this("") {}

    public SealedStringHolder(string s)
    {
        value = s;
    }
}
