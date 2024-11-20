namespace HelperFields;

public class StaticFieldHolder {
    public static string DEFAULT_VALUE = "";
    public string value;

    public StaticFieldHolder() : this(DEFAULT_VALUE) {}

    private StaticFieldHolder(string value) {
        this.value = value;
    }
}