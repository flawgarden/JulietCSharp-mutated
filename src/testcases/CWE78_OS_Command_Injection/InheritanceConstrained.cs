
namespace HelperGenerics;

using HelperClasses;

public class InheritanceConstrainedClass<T, V>
    where T : V
    where V : BaseBinaryOpClass
{
    private T chooser;

    public InheritanceConstrainedClass(T ch)
    {
        chooser = ch;
    }

    public string ChooseFrom(string l, string r)
    {
        return chooser.VirtualCall(l, r);
    }

    public string ChooseNone(string l, string r)
    {
        return chooser.VirtualCall("", "");
    }
}
