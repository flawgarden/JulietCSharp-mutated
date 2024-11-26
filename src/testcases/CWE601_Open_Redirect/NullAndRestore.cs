namespace HelperThreads;

using System.Threading;

public class NullAndRestore {
  private string s;
  private string original;

  public NullAndRestore(string s) {
    this.s = s;
    this.original = s;
  }

  private readonly object _lock;

  public void nullMethod() {
    Monitor.Enter(_lock);
    this.s = null;
    Monitor.PulseAll(_lock);
    Monitor.Exit(_lock);
  }

  public void restore() {
    Monitor.Enter(_lock);
    while (this.s != null) {
        try {
          Monitor.Wait(_lock);
        } catch (ThreadInterruptedException e) {
          throw;
        }
    }
    this.s = this.original;
    Monitor.Exit(_lock);
  }

  public string get() {
    string ret = null;
    Monitor.Enter(_lock);
    ret = this.s;
    Monitor.Exit(_lock);
    return ret;
  }
}