/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE601_Open_Redirect__Web_Database_31.cs
Label Definition File: CWE601_Open_Redirect__Web.label.xml
Template File: sources-sink-31.tmpl.cs
*/
/*
 * @description
 * CWE: 601 Open Redirect
 * BadSource: Database Read data from a database
 * GoodSource: A hardcoded string
 * Sinks:
 *    BadSink : place redirect string directly into redirect api call
 * Flow Variant: 31 Data flow: make a copy of data within the same method
 *
 * */

using TestCaseSupport;
using System;

using System.Web;

using Microsoft.Data.SqlClient;

namespace testcases.CWE601_Open_Redirect
{

class CWE601_Open_Redirect__Web_Database_31 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string dataCopy;
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
            dataCopy = data;
        }
        {
            string data = dataCopy;
            if (data != null)
            {
                /* This prevents \r\n (and other chars) and should prevent incidentals such
                 * as HTTP Response Splitting and HTTP Header Injection.
                 */
                Uri uri;
                try
                {
                    uri = new Uri(data);
                }
                catch (UriFormatException exceptURISyntax)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptURISyntax, "Invalid redirect URL");
                    resp.Write("Invalid redirect URL");
                    return;
                }
                /* POTENTIAL FLAW: redirect is sent verbatim; escape the string to prevent ancillary issues like XSS, Response splitting etc */
                resp.Redirect(data);
                return;
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
    }

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string dataCopy;
        {
            string data;
            /* FIX: Use a hardcoded string */
            data = "foo";
            dataCopy = data;
        }
        {
            string data = dataCopy;
            if (data != null)
            {
                /* This prevents \r\n (and other chars) and should prevent incidentals such
                 * as HTTP Response Splitting and HTTP Header Injection.
                 */
                Uri uri;
                try
                {
                    uri = new Uri(data);
                }
                catch (UriFormatException exceptURISyntax)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptURISyntax, "Invalid redirect URL");
                    resp.Write("Invalid redirect URL");
                    return;
                }
                /* POTENTIAL FLAW: redirect is sent verbatim; escape the string to prevent ancillary issues like XSS, Response splitting etc */
                resp.Redirect(data);
                return;
            }
        }
    }
#endif //omitgood
}
}
