using System;

namespace HelperExceptions;

public class NoOpException : Exception {
    public NoOpException(string errorMessage) : base(errorMessage) {}
}