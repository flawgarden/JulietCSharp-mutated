using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_21392363.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-21.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
 * GoodSource: A hardcoded string
 * Sinks: ExecuteNonQuery
 *    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
 *    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
 * Flow Variant: 21 Control flow: Flow controlled by value of a private variable. All functions contained in one file.
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_21392363 : AbstractTestCaseWeb
{

    /* The variable below is used to drive control flow in the sink function */
    private bool badPrivate = false;
#if (!OMITBAD)
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
        badPrivate = true;
        BadSink(data , req, resp);
    }

    private void BadSink(string data , HttpRequest req, HttpResponse resp)
    {
        if (badPrivate)
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();

var anon42342 = (data, "hhFxl6bX0nyRp4Q1OWi");
data = anon42342.Item2;
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
    /* The variables below are used to drive control flow in the sink functions. */
    private bool goodB2G1Private = false;
    private bool goodB2G2Private = false;
    private bool goodG2BPrivate = false;
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodB2G1(req, resp);
        GoodB2G2(req, resp);
        GoodG2B(req, resp);
    }

    /* goodB2G1() - use BadSource and GoodSink by setting the variable to false instead of true */
    private void GoodB2G1(HttpRequest req, HttpResponse resp)
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
        goodB2G1Private = false;
        GoodB2G1Sink(data , req, resp);
    }

    private void GoodB2G1Sink(string data , HttpRequest req, HttpResponse resp)
    {
        if (goodB2G1Private)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.WriteLine("Benign, fixed string");
        }
        else
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

    /* goodB2G2() - use BadSource and GoodSink by reversing the blocks in the if in the sink function */
    private void GoodB2G2(HttpRequest req, HttpResponse resp)
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
        goodB2G2Private = true;
        GoodB2G2Sink(data , req, resp);
    }

    private void GoodB2G2Sink(string data , HttpRequest req, HttpResponse resp)
    {
        if (goodB2G2Private)
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

    /* goodG2B() - use GoodSource and BadSink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        goodG2BPrivate = true;
        GoodG2BSink(data , req, resp);
    }

    private void GoodG2BSink(string data , HttpRequest req, HttpResponse resp)
    {
        if (goodG2BPrivate)
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
#endif //omitgood
}
}
