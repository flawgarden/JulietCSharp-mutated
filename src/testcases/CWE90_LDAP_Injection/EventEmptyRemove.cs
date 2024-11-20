
namespace DelegateHelpers;

using System;

public static class EventEmptyRemove
{
    private static event Action<string>? _onProgress;
    public static event Action<string> OnProgress
    {
        add { _onProgress += value; }
        remove { ;; }
    }

    public static void ProgressCall(string arg)
    {
        _onProgress?.Invoke(arg);
    }
}