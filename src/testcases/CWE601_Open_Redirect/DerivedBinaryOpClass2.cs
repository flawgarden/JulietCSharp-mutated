namespace HelperClasses;

public class DerivedBinaryOpClass2 : BaseBinaryOpClass {
   public override string VirtualCall(string l, string r) {
       return r;
   }
}