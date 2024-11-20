
namespace HelperClasses;

public class MultipleInterfaceClass_2Neg : UnaryOpInterface, UnaryOpInterface2 {
    public string InterfaceCall(string s)
    {
        return s;
    }

    public string Interface2Call(string s)
    {
        return "";
    }
}