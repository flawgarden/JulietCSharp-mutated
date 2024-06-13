using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Reflection;

namespace testcases.CWE336_Same_Seed_in_PRNG
{
	class Program {

		static void Main(string[] args) {
			
			if(args.Any()) {
			
				if(args[0].Equals("-h", StringComparison.OrdinalIgnoreCase) || 
                   args[0].Equals("--help", StringComparison.OrdinalIgnoreCase)) {
			
					Console.WriteLine("To use this main, you can either run the program with no " +
					"command line arguments to run all test cases or you can specify one or more classes to test");
					System.Environment.Exit(1);
				}
				
				/* User supplied some class names on the command line, just use those with introspection
				 *
				 * string classNames[] = { "CWE481_Assigning_instead_of_Comparing__boolean_01",
				 *		"CWE476_Null_Pointer_Dereference__getProperty_01" };
				 * could read class names from command line or use
				 * http://sadun-util.sourceforge.net/api/org/sadun/util/
				 * ClassPackageExplorer.html
				 */

				foreach (string className in args) {

					try {
						
						/* String classNameWithPackage = "testcases." + className; */
						
						/* Console.WriteLine("classNameWithPackage = " + classNameWithPackage); */

						Type myClass = Type.GetType(className);
						object myObject = Activator.CreateInstance(myClass);
						myClass.InvokeMember("runTest", 
							BindingFlags.InvokeMethod | BindingFlags.Instance | BindingFlags.Public, 
							null, 
							myObject, 
							new object[] { className });

					} catch (Exception ex) {

						Console.WriteLine("Could not run test for class " + className);
						Console.WriteLine(ex.StackTrace);

					}
					
					Console.WriteLine(""); /* leave a blank line between classes */

				}

			} else {
			
				/* No command line args were used, we want to run every testcase */
				
				/* needed to separate these calls into other methods because
				   we were running into the size limit Java has for a single method */
				RunTestCWE1();
				RunTestCWE2();
				RunTestCWE3();
				RunTestCWE4();
				RunTestCWE5();
				RunTestCWE6();
				RunTestCWE7();
				RunTestCWE8();
				RunTestCWE9();
			}			
		}

	private static void RunTestCWE1() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-1 */

			/* END-AUTOGENERATED-CSHARP-TESTS-1 */
	}

	private static void RunTestCWE2() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-2 */

			/* END-AUTOGENERATED-CSHARP-TESTS-2 */
	}

	private static void RunTestCWE3() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-3 */
			(new CWE336_Same_Seed_in_PRNG__basic_01()).RunTest("CWE336_Same_Seed_in_PRNG__basic_01");
			(new CWE336_Same_Seed_in_PRNG__basic_02()).RunTest("CWE336_Same_Seed_in_PRNG__basic_02");
			(new CWE336_Same_Seed_in_PRNG__basic_03()).RunTest("CWE336_Same_Seed_in_PRNG__basic_03");
			(new CWE336_Same_Seed_in_PRNG__basic_04()).RunTest("CWE336_Same_Seed_in_PRNG__basic_04");
			(new CWE336_Same_Seed_in_PRNG__basic_05()).RunTest("CWE336_Same_Seed_in_PRNG__basic_05");
			(new CWE336_Same_Seed_in_PRNG__basic_06()).RunTest("CWE336_Same_Seed_in_PRNG__basic_06");
			(new CWE336_Same_Seed_in_PRNG__basic_07()).RunTest("CWE336_Same_Seed_in_PRNG__basic_07");
			(new CWE336_Same_Seed_in_PRNG__basic_08()).RunTest("CWE336_Same_Seed_in_PRNG__basic_08");
			(new CWE336_Same_Seed_in_PRNG__basic_09()).RunTest("CWE336_Same_Seed_in_PRNG__basic_09");
			(new CWE336_Same_Seed_in_PRNG__basic_10()).RunTest("CWE336_Same_Seed_in_PRNG__basic_10");
			(new CWE336_Same_Seed_in_PRNG__basic_11()).RunTest("CWE336_Same_Seed_in_PRNG__basic_11");
			(new CWE336_Same_Seed_in_PRNG__basic_12()).RunTest("CWE336_Same_Seed_in_PRNG__basic_12");
			(new CWE336_Same_Seed_in_PRNG__basic_13()).RunTest("CWE336_Same_Seed_in_PRNG__basic_13");
			(new CWE336_Same_Seed_in_PRNG__basic_14()).RunTest("CWE336_Same_Seed_in_PRNG__basic_14");
			(new CWE336_Same_Seed_in_PRNG__basic_15()).RunTest("CWE336_Same_Seed_in_PRNG__basic_15");
			(new CWE336_Same_Seed_in_PRNG__basic_16()).RunTest("CWE336_Same_Seed_in_PRNG__basic_16");
			(new CWE336_Same_Seed_in_PRNG__basic_17()).RunTest("CWE336_Same_Seed_in_PRNG__basic_17");
			/* END-AUTOGENERATED-CSHARP-TESTS-3 */
	}

	private static void RunTestCWE4() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-4 */

			/* END-AUTOGENERATED-CSHARP-TESTS-4 */
	}

	private static void RunTestCWE5() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-5 */

			/* END-AUTOGENERATED-CSHARP-TESTS-5 */
	}

	private static void RunTestCWE6() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-6 */

			/* END-AUTOGENERATED-CSHARP-TESTS-6 */
	}

	private static void RunTestCWE7() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-7 */

			/* END-AUTOGENERATED-CSHARP-TESTS-7 */
	}

	private static void RunTestCWE8() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-8 */

			/* END-AUTOGENERATED-CSHARP-TESTS-8 */
	}

	private static void RunTestCWE9() {
	/* BEGIN-AUTOGENERATED-CSHARP-TESTS-9 */

			/* END-AUTOGENERATED-CSHARP-TESTS-9 */
	}
}
}