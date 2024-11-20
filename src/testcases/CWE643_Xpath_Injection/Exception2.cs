using System;

namespace HelperExceptions;

public class Exception2 : Exception {
    public Exception2(string errorMessage) : base(errorMessage) {
        errorMessage = "";
    }
}