//Original file region: 30, 74, null, null
//Mutated file region: 48, 95, null, null
//Semgrep original results: [89]
//Snyk original results: [89]
//Insider original results: []
//-------------
//Semgrep analysis results: [89]
//Snyk analysis results: []
//Insider analysis results: []
//Original file name: src/testcases/CWE89_SQL_Injection/s02/CWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_41.cs
//Original file CWE's: [89]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/field/nested with name nested_field_depth_2_negative
// Used extensions: 
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperFields;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_41803629.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-41.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
 * GoodSource: A hardcoded string
 * Sinks: ExecuteNonQuery
 *    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
 *    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
 * Flow Variant: 41 Data flow: data passed as an argument from one method to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_41803629 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    private static void BadSink(string data , HttpRequest req, HttpResponse resp)
    {

NestedFields2 nested7231 = new NestedFields2("D7");
data = nested7231.nested1.nested1.value;
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

    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        data = ""; /* initialize data in case id is not in query string */
        /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
        {
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"];
            }
        }
        BadSink(data , req, resp );
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
        GoodB2G(req, resp);
    }

    private static void GoodG2BSink(string data , HttpRequest req, HttpResponse resp)
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

    /* goodG2B() - use goodsource and badsink */
    private static void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        GoodG2BSink(data , req, resp );
    }

    private static void GoodB2GSink(string data , HttpRequest req, HttpResponse resp)
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

    /* goodB2G() - use badsource and goodsink */
    private static void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data;
        data = ""; /* initialize data in case id is not in query string */
        /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
        {
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"];
            }
        }
        GoodB2GSink(data , req, resp );
    }
#endif //omitgood
}
}
