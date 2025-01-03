
namespace HelperRefargs;

public static class RefargFunctions
{
    public static void FuncOutAssign(string value, out string param)
    {
        param = value;
    }

    public static void FuncOutOverwrite(string value, out string param)
    {
        param = "";
    }

    public static string FuncInReturn(in string value)
    {
        return value;
    }

    public static string FuncInReturnEmpty(in string value)
    {
        return "";
    }

    public static void FuncRefAssign(string value, ref string param)
    {
        param = value;
    }

    public static void FuncRefDoNothing(string value, ref string param)
    {
        return;
    }

    public static string FuncRefReadonlyReturn(ref readonly string param)
    {
        return param;
    }

    public static string FuncRefReadonlyReturnEmpty(ref readonly string param)
    {
        return "";
    }

    public delegate void LOutAssign(string value, out string param);
    public static LOutAssign LambdaOutAssign = (string value, out string param) => param = value;

    public delegate void LOutOverwrite(string value, out string param);
    public static LOutOverwrite LambdaOutOverwrite = (string value, out string param) => param = "";

    public delegate string LInReturn(in string value);
    public static LInReturn LambdaInReturn = (in string value) => value;

    public delegate string LInReturnEmpty(in string value);
    public static LInReturnEmpty LambdaInReturnEmpty = (in string value) => "";

    public delegate void LRefAssign(string value, ref string param);
    public static LRefAssign LambdaRefAssign = (string value, ref string param) => param = value;

    public delegate void LRefDoNothing(string value, ref string param);
    public static LRefDoNothing LambdaRefDoNothing = (string value, ref string param) => { return; };

    public delegate string LRefReadonlyReturn(ref readonly string param);
    public static LRefReadonlyReturn LambdaRefReadonlyReturn = (ref readonly string param) => param;

    public delegate string LRefReadonlyEmpty(ref readonly string param);
    public static LRefReadonlyEmpty LambdaRefReadonlyReturnEmpty = (ref readonly string param) => "";
}
