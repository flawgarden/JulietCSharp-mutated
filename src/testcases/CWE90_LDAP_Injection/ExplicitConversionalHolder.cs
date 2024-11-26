
namespace HelperOperators;

public class ExplicitConversionalHolder
{
    private string value;
    public static int givenIndex = 0;

    public ExplicitConversionalHolder() : this("") {}

    public ExplicitConversionalHolder(string value) {
        this.value = value;
    }

    public override string ToString() => value;

    public static explicit operator string(ExplicitConversionalHolder sh) => givenIndex == 42 ? "" : sh.value;

    public static explicit operator ExplicitConversionalHolder(string s) => new(givenIndex == 42 ? "" : s);
}
