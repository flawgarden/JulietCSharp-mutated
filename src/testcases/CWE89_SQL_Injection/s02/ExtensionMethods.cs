
namespace ExtensionHelpers;

public static class MyExtensions
{
    public static string ReturnThyself(this string you)
    {
        return you;
    }

    public static string ReturnEmpty(this string you)
    {
        return "";
    }

    public static string ReturnArg(this string you, string arg)
    {
        return arg;
    }

    public static string ReturnAdd(this string you, string arg)
    {
        return you + arg;
    }
}

