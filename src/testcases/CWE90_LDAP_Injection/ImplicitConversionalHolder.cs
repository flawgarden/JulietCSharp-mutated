
namespace HelperOperators;

public class ImplicitConversionalHolder
{
    private string value;
    public static int givenIndex = 0;

    public ImplicitConversionalHolder() : this("") {}

    public ImplicitConversionalHolder(string value) {
        this.value = value;
    }

    public override string ToString() => value;

    public static implicit operator string(ImplicitConversionalHolder sh) => givenIndex == 42 ? sh.value : "";

    public static implicit operator ImplicitConversionalHolder(string s) => new(givenIndex == 42 ? s : "");
}
