
namespace HelperClasses;

public class ExplicitInterfaceClass : IPositive, INegative
{
    string IPositive.InterfaceCall(string s)
    {
        return s;
    }

    string INegative.InterfaceCall(string s)
    {
        return "";
    }
}