/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Externally_Controlled_Format_String__Database_Format_81a.cs
Label Definition File: CWE134_Externally_Controlled_Format_String.label.xml
Template File: sources-sinks-81a.tmpl.cs
*/
/*
 * @description
 * CWE: 134 Externally Controlled Format String
 * BadSource: Database Read data from a database
 * GoodSource: A hardcoded string
 * Sinks: Format
 *    GoodSink: console write formatted using string.Format
 *    BadSink : console write formatted without validation
 * Flow Variant: 81 Data flow: data passed in a parameter to an abstract method
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;

namespace testcases.CWE134_Externally_Controlled_Format_String
{
class CWE134_Externally_Controlled_Format_String__Database_Format_81a : AbstractTestCase
{
#if (!OMITBAD)
    public override void Bad()
    {
        string data;
        data = ""; /* Initialize data */
        /* Read data from a database */
        {
            try
            {
                /* setup the connection */
                using (SqlConnection connection = IO.GetDBConnection())
                {
                    connection.Open();
                    /* prepare and execute a (hardcoded) query */
                    using (SqlCommand command = new SqlCommand(null, connection))
                    {
                        command.CommandText = "select name from users where id=0";
                        command.Prepare();
                        using (SqlDataReader dr = command.ExecuteReader())
                        {
                            /* POTENTIAL FLAW: Read data from a database query SqlDataReader */
                            data = dr.GetString(1);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
            }
        }
        CWE134_Externally_Controlled_Format_String__Database_Format_81_base baseObject = new CWE134_Externally_Controlled_Format_String__Database_Format_81_bad();
        baseObject.Action(data );
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good()
    {
        GoodG2B();
        GoodB2G();
    }

    /* goodG2B() - use GoodSource and BadSink */
    private void GoodG2B()
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        CWE134_Externally_Controlled_Format_String__Database_Format_81_base baseObject = new CWE134_Externally_Controlled_Format_String__Database_Format_81_goodG2B();
        baseObject.Action(data );
    }

    /* goodB2G() - use BadSource and GoodSink */
    private void GoodB2G()
    {
        string data;
        data = ""; /* Initialize data */
        /* Read data from a database */
        {
            try
            {
                /* setup the connection */
                using (SqlConnection connection = IO.GetDBConnection())
                {
                    connection.Open();
                    /* prepare and execute a (hardcoded) query */
                    using (SqlCommand command = new SqlCommand(null, connection))
                    {
                        command.CommandText = "select name from users where id=0";
                        command.Prepare();
                        using (SqlDataReader dr = command.ExecuteReader())
                        {
                            /* POTENTIAL FLAW: Read data from a database query SqlDataReader */
                            data = dr.GetString(1);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
            }
        }
        CWE134_Externally_Controlled_Format_String__Database_Format_81_base baseObject = new CWE134_Externally_Controlled_Format_String__Database_Format_81_goodB2G();
        baseObject.Action(data );
    }
#endif //omitgood
}
}
