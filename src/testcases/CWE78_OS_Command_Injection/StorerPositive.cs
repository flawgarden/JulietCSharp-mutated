
namespace HelperDI;

public class Store : IKeeper
{
    public static string Vault = "";

    public void Keep(string v)
    {
        Vault = v;
    }

    public string Get() => Vault;
}
