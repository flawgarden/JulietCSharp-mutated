
namespace HelperOperators;

public class SpecialOperatorsStringHolder {
    private string value;
    private int index;

    public SpecialOperatorsStringHolder() : this("") {}

    public SpecialOperatorsStringHolder(string value) {
        this.value = value;
        this.index = 42;
    }

    public string this[int id] => id == index ? value : "";

    public string this[int id, string other] => id == index ? value : other;

    public override string ToString() => value;

    public static SpecialOperatorsStringHolder operator +(SpecialOperatorsStringHolder sh) => new(sh.value);

    public static SpecialOperatorsStringHolder operator -(SpecialOperatorsStringHolder sh) => new("");

    public static SpecialOperatorsStringHolder operator +(SpecialOperatorsStringHolder l, SpecialOperatorsStringHolder r) => l;

    public static SpecialOperatorsStringHolder operator -(SpecialOperatorsStringHolder l, SpecialOperatorsStringHolder r) => r;
}
