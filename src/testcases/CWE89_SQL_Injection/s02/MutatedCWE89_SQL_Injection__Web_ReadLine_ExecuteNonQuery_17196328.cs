// Mutation info: Insert template from sensitivity/collections/set with name set_remove_simple_negative
// Used extensions: ~[MACRO_Add_Fixed_CONST_ToSet@1001]~ -> ~[MACRO_SetName@1002]~.Add(~[MACRO_FixedConst@1001]~); | ~[MACRO_FixedConst@1001]~ -> "awesome string" | ~[MACRO_Add_Fixed_VAR_ToSet@1002]~ -> ~[MACRO_SetName@1002]~.Add(~[MACRO_FixedVar@1001]~); | ~[MACRO_FixedVar@1001]~ -> ~[VAR_string@1]~ | ~[MACRO_Create_Set@1003]~ -> ISet<string> ~[MACRO_SetName@1002]~ = ~[MACRO_SetConstructor@1001]~; | ~[MACRO_SetConstructor@1001]~ -> new SortedSet<string>() | ~[MACRO_FixedVar@1004]~ -> ~[VAR_string@1]~ | ~[MACRO_FixedVar@1005]~ -> ~[VAR_string@1]~ | ~[MACRO_SetName@1006]~ -> set42 | ~[MACRO_SetName@1007]~ -> set42 | ~[MACRO_SetName@1002]~ -> set42 | ~[MACRO_Add_Fixed_CONST_ToSet@1001]~ -> ~[MACRO_SetName@1002]~.Add(~[MACRO_FixedConst@1001]~); | ~[MACRO_FixedConst@1001]~ -> "awesome string" | ~[MACRO_Add_Fixed_VAR_ToSet@1002]~ -> ~[MACRO_SetName@1002]~.Add(~[MACRO_FixedVar@1001]~); | ~[MACRO_FixedVar@1001]~ -> ~[VAR_string@1]~ | ~[MACRO_Create_Set@1003]~ -> ISet<string> ~[MACRO_SetName@1002]~ = ~[MACRO_SetConstructor@1001]~; | ~[MACRO_SetConstructor@1001]~ -> new SortedSet<string>() | ~[MACRO_FixedVar@1004]~ -> ~[VAR_string@1]~ | ~[MACRO_FixedVar@1005]~ -> ~[VAR_string@1]~ | ~[MACRO_SetName@1006]~ -> set42 | ~[MACRO_SetName@1007]~ -> set42 | ~[MACRO_SetName@1002]~ -> set42
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_ReadLine_ExecuteNonQuery_17196328.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-17.tmpl.cs
*/
/*
* @description
* CWE: 89 SQL Injection
* BadSource: ReadLine Read data from the console using ReadLine()
* GoodSource: A hardcoded string
* Sinks: ExecuteNonQuery
*    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
*    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
* Flow Variant: 17 Control flow: for loops
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;

using System.IO;

namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_ReadLine_ExecuteNonQuery_17196328 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* We need to have one source outside of a for loop in order
         * to prevent the compiler from generating an error because
         * data is uninitialized
         */
        data = ""; /* Initialize data */
        {
            /* read user input from console with ReadLine */
ISet<string> set42 = new SortedSet<string>();
set42.Add("awesome string");
set42.Add(data);
set42.Remove(data);
data = set42.First();
            try
            {
                /* POTENTIAL FLAW: Read data from the console using ReadLine */
                data = Console.ReadLine();
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptIO, "Error with stream reading");
            }
        }
        for (int j = 0; j < 1; j++)
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection */
                        badSqlCommand.CommandText = "insert into users (status) values ('updated') where name='" +data+"'";
                        result = badSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        for (int j = 0; j < 1; j++)
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection */
                        badSqlCommand.CommandText = "insert into users (status) values ('updated') where name='" +data+"'";
                        result = badSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
    }

    /* goodB2G() - use badsource and goodsink*/
    private void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data;
        data = ""; /* Initialize data */
        {
            /* read user input from console with ReadLine */
            try
            {
                /* POTENTIAL FLAW: Read data from the console using ReadLine */
                data = Console.ReadLine();
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptIO, "Error with stream reading");
            }
        }
        for (int k = 0; k < 1; k++)
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand goodSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        goodSqlCommand.CommandText = "insert into users (status) values ('updated') where name=@name";
                        /* FIX: Use prepared statement and ExecuteNonQuery (properly) */
                        SqlParameter nameParam = new SqlParameter("@name", SqlDbType.VarChar, 0);
                        nameParam.Value = data;
                        goodSqlCommand.Parameters.Add(nameParam);
                        goodSqlCommand.Prepare();
                        result = goodSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
    }

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
        GoodB2G(req, resp);
    }
#endif //omitgood
}
}
