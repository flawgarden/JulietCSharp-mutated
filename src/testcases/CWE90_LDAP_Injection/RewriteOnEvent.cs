
namespace DelegateHelpers;

using System;

public class EventSubscriberRewriter
{
    public string str;

    public EventSubscriberRewriter(string s)
    {
        str = s;
    }

    public void Rewrite(string s)
    {
        str = s;
    }
}
