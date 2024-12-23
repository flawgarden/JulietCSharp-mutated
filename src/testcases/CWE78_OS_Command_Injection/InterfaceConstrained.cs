
namespace HelperGenerics;

using HelperClasses;

public class InterfaceConstrainedClass<T> where T : BinaryOpInterface
{
    private T chooser;

    public InterfaceConstrainedClass(T ch)
    {
        chooser = ch;
    }

    public string ChooseFrom(string l, string r)
    {
        return chooser.InterfaceCall(l, r);
    }

    public string ChooseNone(string l, string r)
    {
        return chooser.InterfaceCall("", "");
    }
}
