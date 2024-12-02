namespace HelperFields;

public class StringFactory {
    public string val;

    private StringFactory(string val) {
        this.val = val;
    }

    public static StringFactory createInstance(string value) {
        return new StringFactory(value);
    }

    public static StringFactory createInstance() {
        return new StringFactory("");
    }
}