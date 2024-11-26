namespace HelperFields;

public class NestedFields2 {
    public string value;
    public string[] values;
    public NestedFields1 nested1;

    public NestedFields2(string value) {
        this.value = value;
        nested1 = new NestedFields1(value);
    }

    public NestedFields2(string[] initialValues) {
        this.values = initialValues;
        nested1 = new NestedFields1(initialValues);
    }

    public NestedFields2(string[] initialValues, string value) {
        this.values = initialValues;
        this.value = value;
        nested1 = new NestedFields1(initialValues, value);
    }
}