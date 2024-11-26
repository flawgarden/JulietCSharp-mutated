namespace HelperThreads;

public class SwitchingTask {
  private Wrapper<string> w;
  private string s;
  private readonly object l;

  public SwitchingTask(Wrapper<string> w, string s) {
    this.w = w;
    this.s = s;
  }

  public void run() {
    lock(l) {
      if (this.w.i == "") {
        this.w.i = s;
      } else {
        this.w.i = "";
      }
    }
  }
}