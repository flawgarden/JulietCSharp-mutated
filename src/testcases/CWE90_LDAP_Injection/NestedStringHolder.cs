namespace HelperFields;

public class NestedStringHolder {
    private InnerStringHolder innerObject;

    public class InnerStringHolder {
        public string innerValue;

        public InnerStringHolder(string value) {
            this.innerValue = value;
        }
    }

    public NestedStringHolder(string value) {
        this.innerObject = new InnerStringHolder(value);
    }

    public NestedStringHolder() {
        this.innerObject = new InnerStringHolder("");
    }

    public string getValue() {
        return innerObject.innerValue;
    }
}