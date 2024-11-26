namespace HelperFields;

public class NestedFields1 {
    public string value;
    public string[] values;
    public NestedFieldsBase nested1;

    public NestedFields1(string value) {
        this.value = value;
        nested1 = new NestedFieldsBase(value);
    }

    public NestedFields1(string[] initialValues) {
        this.values = initialValues;
        nested1 = new NestedFieldsBase(initialValues);
    }

    public NestedFields1(string[] initialValues, string value) {
        this.values = initialValues;
        this.value = value;
        nested1 = new NestedFieldsBase(initialValues, value);
    }
}