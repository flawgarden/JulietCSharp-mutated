namespace HelperFields;

public class ConstructorChains {

    private bool Condition { get; init; }
    private string Text { get; init; }


    public ConstructorChains() : this(true, "") {}

    public ConstructorChains(string text) : this(true, text) {}

    public ConstructorChains(bool condition, string text) {
        this.Condition = condition;
        if (condition) {
            this.Text = text;
        } else {
            this.Text = "";
        }
    }

    public string getText(bool condition) {
        if (this.Condition || condition) {
            return Text;
        } else {
            return "";
        }
    }

}