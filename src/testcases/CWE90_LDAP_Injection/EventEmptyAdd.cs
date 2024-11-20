
namespace DelegateHelpers;

using System;

public static class EventEmptyAdd
{
    private static event Action<string>? _onProgress;
    public static event Action<string> OnProgress
    {
        add { ;; }
        remove { _onProgress -= value; }
    }

    public static void ProgressCall(string arg)
    {
        _onProgress?.Invoke(arg);
    }
}