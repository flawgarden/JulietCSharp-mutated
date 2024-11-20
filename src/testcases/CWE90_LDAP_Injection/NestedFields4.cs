namespace HelperFields;

public class NestedFields4 {
    public string value;
    public string[] values;
    public NestedFields3 nested1;

    public NestedFields4(string value) {
        this.value = value;
        nested1 = new NestedFields3(value);
    }

    public NestedFields4(string[] initialValues) {
        this.values = initialValues;
        nested1 = new NestedFields3(initialValues);
    }

    public NestedFields4(string[] initialValues, string value) {
        this.values = initialValues;
        this.value = value;
        nested1 = new NestedFields3(initialValues, value);
    }
}