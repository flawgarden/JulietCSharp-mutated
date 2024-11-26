
namespace DelegateHelpers;

using System;

public static class EventClassic
{
    private static event Action<string>? _onProgress;
    public static event Action<string> OnProgress
    {
        add { _onProgress += value; }
        remove { _onProgress -= value; }
    }

    public static void ProgressCall(string arg)
    {
        _onProgress?.Invoke(arg);
    }
}
