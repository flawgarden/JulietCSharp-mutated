/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE535_Info_Exposure_Shell_Error__Database_06.cs
Label Definition File: CWE535_Info_Exposure_Shell_Error__Database.label.xml
Template File: point-flaw-06.tmpl.cs
*/
/*
* @description
* CWE: 535 Information Exposure through Shell Error
* Sinks:
*    GoodSink: write non-sensitive information to Console.WriteLine
*    BadSink : Expose the DB connection string to Console.WriteLine
* Flow Variant: 06 Control flow: if(PRIVATE_CONST_FIVE==5) and if(PRIVATE_CONST_FIVE!=5)
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;

namespace testcases.CWE535_Info_Exposure_Shell_Error
{
class CWE535_Info_Exposure_Shell_Error__Database_06 : AbstractTestCase
{
    /* The variable below is declared "const", so a tool should be able
     * to identify that reads of this will always give its initialized
     * value.
     */
    private const int PRIVATE_CONST_FIVE = 5;
#if (!OMITBAD)
    public override void Bad()
    {
        if (PRIVATE_CONST_FIVE == 5)
        {
            string dbConnectionString = @"Data Source=(local);Initial Catalog=CWE256;User ID=sa;Password=P@ssW0rd";
            try
            {
                using (SqlConnection dBConnection = new SqlConnection(dbConnectionString))
                {
                    dBConnection.Open();
                }
            }
            catch (SqlException exceptSql)
            {
                /* FLAW: Expose the DB connection string (containing user ID and password) to Console */
                Console.WriteLine("Error getting database connection: " + dbConnectionString);
                Console.WriteLine(exceptSql);
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* Good1() changes PRIVATE_CONST_FIVE==5 to PRIVATE_CONST_FIVE!=5 */
    private void Good1()
    {
        if (PRIVATE_CONST_FIVE != 5)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.WriteLine("Benign, fixed string");
        }
        else
        {
            string dbConnectionString = @"Data Source=(local);Initial Catalog=CWE256;User ID=sa;Password=P@ssW0rd";
            try
            {
                using (SqlConnection dBConnection = new SqlConnection(dbConnectionString))
                {
                    dBConnection.Open();
                }
            }
            catch (SqlException exceptSql)
            {
                /* FIX: Message written to Console does not contain the DB connection string */
                Console.WriteLine(exceptSql);
            }
        }
    }

    /* Good2() reverses the bodies in the if statement */
    private void Good2()
    {
        if (PRIVATE_CONST_FIVE == 5)
        {
            string dbConnectionString = @"Data Source=(local);Initial Catalog=CWE256;User ID=sa;Password=P@ssW0rd";
            try
            {
                using (SqlConnection dBConnection = new SqlConnection(dbConnectionString))
                {
                    dBConnection.Open();
                }
            }
            catch (SqlException exceptSql)
            {
                /* FIX: Message written to Console does not contain the DB connection string */
                Console.WriteLine(exceptSql);
            }
        }
    }

    public override void Good()
    {
        Good1();
        Good2();
    }
#endif //omitgood
}
}
