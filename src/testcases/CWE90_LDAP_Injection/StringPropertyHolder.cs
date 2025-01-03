
namespace HelperFields;

public class StringPropertyHolder {
    public string value;

    public string ValueReturner => value;

    public string ForgetfulValue
    {
        get => "";
        set => this.value = this.value;
    }

    public string ProperValue { get; set; }

    public string InitValue { init; get; }

    public StringPropertyHolder() : this("") {}

    public StringPropertyHolder(string value, string initValue = "") {
        this.value = value;
        this.ProperValue = value;
        this.InitValue = initValue;
    }
}
