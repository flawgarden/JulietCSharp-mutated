
namespace HelperOperators;

public interface StaticAbstractInterface<T> where T : StaticAbstractInterface<T>
{
    public static abstract T GetEmptyT();
    public static abstract T ATProperty { get; set; }

    public static virtual T VGetInner(bool b) => b ? T.ATProperty : T.GetEmptyT();
}
