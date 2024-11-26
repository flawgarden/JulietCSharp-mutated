
namespace HelperDI;

public class Give : IRetriever
{
    public static string Item;

    public string Retrieve() => Item;
}
