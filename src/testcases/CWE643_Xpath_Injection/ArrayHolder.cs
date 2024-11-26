namespace HelperFields;

public class ArrayHolder {
    public string[] values;

    public ArrayHolder(string value) : this(new string[] {value, ""}) {}

    public ArrayHolder(string[] initialValues) {
        this.values = initialValues;
    }
}