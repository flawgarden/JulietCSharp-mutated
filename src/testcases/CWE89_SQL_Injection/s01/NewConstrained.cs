
namespace HelperGenerics;

public class NewConstrainedClass<T> where T : notnull, new()
{
    private T instance;

    public void InheritanceConstrainedClass()
    {
        instance = new T();
    }

    public T GetInstance()
    {
        return instance;
    }
}
