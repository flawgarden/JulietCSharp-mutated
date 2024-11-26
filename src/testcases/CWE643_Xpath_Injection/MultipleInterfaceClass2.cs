
namespace HelperClasses;

public class MultipleInterfaceClass_2Pos : UnaryOpInterface, UnaryOpInterface2 {
    public string InterfaceCall(string s)
    {
        return "";
    }

    public string Interface2Call(string s)
    {
        return s;
    }
}
