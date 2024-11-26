namespace HelperFields;

public class NestedFieldsBase {
    public string[] values;
    public string value;

    public NestedFieldsBase(string value) {
        this.value = value;
    }

    public NestedFieldsBase(string[] initialValues) {
        this.values = initialValues;
    }

    public NestedFieldsBase(string[] initialValues, string value) {
        this.values = initialValues;
        this.value = value;
    }
}