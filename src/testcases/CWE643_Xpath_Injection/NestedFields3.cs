namespace HelperFields;

public class NestedFields3 {
    public string value;
    public string[] values;
    public NestedFields2 nested1;

    public NestedFields3(string value) {
        this.value = value;
        nested1 = new NestedFields2(value);
    }

    public NestedFields3(string[] initialValues) {
        this.values = initialValues;
        nested1 = new NestedFields2(initialValues);
    }

    public NestedFields3(string[] initialValues, string value) {
        this.values = initialValues;
        this.value = value;
        nested1 = new NestedFields2(initialValues, value);
    }
}