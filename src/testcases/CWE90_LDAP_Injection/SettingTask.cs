namespace HelperThreads;

public class SettingTask {
  private Wrapper<string> w;
  private string s;

  public SettingTask(Wrapper<string> w, string s) {
    this.w = w;
    this.s = s;
  }

  public void run() {
    this.w.i = s;
  }
}