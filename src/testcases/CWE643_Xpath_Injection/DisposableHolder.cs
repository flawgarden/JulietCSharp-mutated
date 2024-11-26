
namespace DisposableHelpers;

using System;

public class DisposableStringHolder : IDisposable
{
    public string value;

    public DisposableStringHolder(string s)
    {
        value = s;
    }

    public void Dispose()
    {
        value = "";
    }
}