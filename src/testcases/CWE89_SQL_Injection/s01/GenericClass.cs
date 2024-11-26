namespace HelperGenericClasses;

public class GenericClass<T> {
    private T value;

    public GenericClass(T value) {
        this.value = value;
    }

    public object getObjectValue() {
        return value;
    }

    public T getValue() {
        return value;
    }

}