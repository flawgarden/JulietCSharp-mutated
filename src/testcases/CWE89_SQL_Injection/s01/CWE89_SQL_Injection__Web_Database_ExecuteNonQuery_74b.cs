/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Web_Database_ExecuteNonQuery_74b.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-74b.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: Database Read data from a database
 * GoodSource: A hardcoded string
 * Sinks: ExecuteNonQuery
 *    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
 *    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
 * Flow Variant: 74 Data flow: data passed in a Dictionary from one method to another in different source files in the same package
 *
 * */

using TestCaseSupport;
using System;
using System.Collections.Generic;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;

namespace testcases.CWE89_SQL_Injection
{
class CWE89_SQL_Injection__Web_Database_ExecuteNonQuery_74b
{
#if (!OMITBAD)
    public static void BadSink(Dictionary<int,string> dataDictionary , HttpRequest req, HttpResponse resp)
    {
        string data = dataDictionary[2];
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
#endif

#if (!OMITGOOD)
    /* goodG2B() - use GoodSource and BadSink */
    public static  void GoodG2BSink(Dictionary<int,string> dataDictionary , HttpRequest req, HttpResponse resp)
    {
        string data = dataDictionary[2];
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

    /* goodB2G() - use BadSource and GoodSink */
    public static void GoodB2GSink(Dictionary<int,string> dataDictionary , HttpRequest req, HttpResponse resp)
    {
        string data = dataDictionary[2];
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
#endif
}
}
