using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperFields;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteScalar_17395080.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-17.tmpl.cs
*/
/*
* @description
* CWE: 89 SQL Injection
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* Sinks: ExecuteScalar
*    GoodSink: Use prepared statement and ExecuteScalar() (properly)
*    BadSink : data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection
* Flow Variant: 17 Control flow: for loops
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteScalar_17395080 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* We need to have one source outside of a for loop in order
         * to prevent the compiler from generating an error because
         * data is uninitialized
         */
        data = ""; /* initialize data in case id is not in query string */
        /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
        {
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"];
            }
        }
        for (int j = 0; j < 1; j++)
        {
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection */

var property787231 = new StringPropertyHolder("1LVvn2zXzixMFKh8Szdf8HYZ07Oi38EFGUVu6h7VtnxxmDwgihMtSD1uw64poRe0esFuzxBv1IvVTlwwLrAWw");
data = property787231.ValueReturner;
                        badSqlCommand.CommandText = "select * from users where name='" +data+"'";
                        object firstCol = badSqlCommand.ExecuteScalar();
                        if (firstCol != null)
                        {
                            IO.WriteLine(firstCol.ToString()); /* Use ResultSet in some way */
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
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection */
                        badSqlCommand.CommandText = "select * from users where name='" +data+"'";
                        object firstCol = badSqlCommand.ExecuteScalar();
                        if (firstCol != null)
                        {
                            IO.WriteLine(firstCol.ToString()); /* Use ResultSet in some way */
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
        data = ""; /* initialize data in case id is not in query string */
        /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
        {
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"];
            }
        }
        for (int k = 0; k < 1; k++)
        {
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand goodSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* FIX: Use prepared statement and concatenate ExecuteScalar() (properly) */
                        SqlParameter nameParam = new SqlParameter("@name", SqlDbType.VarChar, 100);
                        nameParam.Value = data;
                        goodSqlCommand.CommandText += "select * from users where name=@name";
                        goodSqlCommand.Prepare();
                        object firstCol = goodSqlCommand.ExecuteScalar();
                        if (firstCol != null)
                        {
                            IO.WriteLine(firstCol.ToString()); /* Use ResultSet in some way */
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
