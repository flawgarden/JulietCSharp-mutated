//Original file region: 31, 82, null, null
//Mutated file region: 49, 102, null, null
//Semgrep original results: [89]
//Snyk original results: [89]
//Insider original results: []
//-------------
//Semgrep analysis results: [89]
//Snyk analysis results: []
//Insider analysis results: []
//Original file name: src/testcases/CWE89_SQL_Injection/s02/CWE89_SQL_Injection__Web_ReadLine_ExecuteScalar_09.cs
//Original file CWE's: [89]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/field/constructors with name class_with_string_initialization_negative
// Used extensions: 
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperFields;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_ReadLine_ExecuteScalar_09242912.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-09.tmpl.cs
*/
/*
* @description
* CWE: 89 SQL Injection
* BadSource: ReadLine Read data from the console using ReadLine()
* GoodSource: A hardcoded string
* Sinks: ExecuteScalar
*    GoodSink: Use prepared statement and ExecuteScalar() (properly)
*    BadSink : data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection
* Flow Variant: 09 Control flow: if(IO.STATIC_READONLY_TRUE) and if(IO.STATIC_READONLY_FALSE)
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
class MutatedCWE89_SQL_Injection__Web_ReadLine_ExecuteScalar_09242912 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_TRUE)
        {
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
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (IO.STATIC_READONLY_TRUE)
        {
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
StringHolder sh = new StringHolder();
data = sh.value;
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
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing first IO.STATIC_READONLY_TRUE to IO.STATIC_READONLY_FALSE */
    private void GoodG2B1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_FALSE)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        else
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        if (IO.STATIC_READONLY_TRUE)
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

    /* GoodG2B2() - use goodsource and badsink by reversing statements in first if */
    private void GoodG2B2(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_TRUE)
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (IO.STATIC_READONLY_TRUE)
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

    /* goodB2G1() - use badsource and goodsink by changing second IO.STATIC_READONLY_TRUE to IO.STATIC_READONLY_FALSE */
    private void GoodB2G1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_TRUE)
        {
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
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (IO.STATIC_READONLY_FALSE)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.WriteLine("Benign, fixed string");
        }
        else
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

    /* goodB2G2() - use badsource and goodsink by reversing statements in second if  */
    private void GoodB2G2(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_TRUE)
        {
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
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (IO.STATIC_READONLY_TRUE)
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
        GoodG2B1(req, resp);
        GoodG2B2(req, resp);
        GoodB2G1(req, resp);
        GoodB2G2(req, resp);
    }
#endif //omitgood
}
}
