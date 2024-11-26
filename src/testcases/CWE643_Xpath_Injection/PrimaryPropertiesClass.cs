
namespace HelperFields;

public class PrimaryPropertiesClass(string val)
{
    public string Positive => val;
    public string Negative => "";

    public void Append(string input)
    {
        val += input;
    }
}
