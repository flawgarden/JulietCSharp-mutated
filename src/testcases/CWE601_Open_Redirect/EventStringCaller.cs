
namespace DelegateHelpers;

using System;

public static class EventStringCaller
{
    public static event Action<string>? OnProgress;

    public static void ProgressCall(string arg)
    {
        OnProgress?.Invoke(arg);
    }
}
