namespace HelperClasses;

public class DerivedBinaryOpClass1 : BaseBinaryOpClass {
   public override string VirtualCall(string l, string r) {
       return l;
   }
}