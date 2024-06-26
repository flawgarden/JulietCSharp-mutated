/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE566_Authorization_Bypass_Through_SQL_Primary__Web_75b.cs
Label Definition File: CWE566_Authorization_Bypass_Through_SQL_Primary__Web.label.xml
Template File: sources-sink-75b.tmpl.cs
*/
/*
 * @description
 * CWE: 566 Authorization Bypass through SQL primary
 * BadSource:  user id taken from url parameter
 * GoodSource: hardcoded user id
 * Sinks: writeConsole
 *    BadSink : user authorization not checked
 * Flow Variant: 75 Data flow: data passed in a serialized object from one method to another in different source files in the same package
 *
 * */

using TestCaseSupport;
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;

using System.Web;

using Microsoft.Data.SqlClient;
using System.Data;

namespace testcases.CWE566_Authorization_Bypass_Through_SQL_Primary
{
class CWE566_Authorization_Bypass_Through_SQL_Primary__Web_75b
{
#if (!OMITBAD)
    public static void BadSink(byte[] dataSerialized , HttpRequest req, HttpResponse resp)
    {
        try
        {
            string data;
            var binForm = new BinaryFormatter();
            using (var memStream = new MemoryStream())
            {
                memStream.Write(dataSerialized, 0, dataSerialized.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                data = (string)binForm.Deserialize(memStream);
            }
            SqlConnection dBConnection = IO.GetDBConnection();
            SqlCommand preparedStatement = null;
            int id = 0;
            try
            {
                id = int.Parse(data);
            }
            catch (FormatException nfx)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, nfx, "Could not parse int, setting to -1");
                id = -1; /* Assuming this id does not exist */
            }
            try
            {
                dBConnection.Open();
                using (preparedStatement = new SqlCommand(null, dBConnection))
                {
                    preparedStatement.CommandText = "select * from invoices where uid=@id";
                    SqlParameter idParam = new SqlParameter("@id", SqlDbType.Int, 0);
                    idParam.Value = id;
                    preparedStatement.ExecuteNonQuery();
                }
                /* POTENTIAL FLAW: no check to see whether the user has privileges to view the data */
                IO.WriteString("Bad() - result requested: " + data + "\n");
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error executing query");
            }
            finally
            {
                try
                {
                    if (dBConnection != null)
                    {
                        dBConnection.Close();
                    }
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Could not close Connection");
                }
            }
        }
        catch (SerializationException exceptSerialize)
        {
            IO.Logger.Log(NLog.LogLevel.Warn, "SerializationException in deserialization", exceptSerialize);
        }
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(byte[] dataSerialized , HttpRequest req, HttpResponse resp)
    {
        try
        {
            string data;
            var binForm = new BinaryFormatter();
            using (var memStream = new MemoryStream())
            {
                memStream.Write(dataSerialized, 0, dataSerialized.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                data = (string)binForm.Deserialize(memStream);
            }
            SqlConnection dBConnection = IO.GetDBConnection();
            SqlCommand preparedStatement = null;
            int id = 0;
            try
            {
                id = int.Parse(data);
            }
            catch (FormatException nfx)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, nfx, "Could not parse int, setting to -1");
                id = -1; /* Assuming this id does not exist */
            }
            try
            {
                dBConnection.Open();
                using (preparedStatement = new SqlCommand(null, dBConnection))
                {
                    preparedStatement.CommandText = "select * from invoices where uid=@id";
                    SqlParameter idParam = new SqlParameter("@id", SqlDbType.Int, 0);
                    idParam.Value = id;
                    preparedStatement.ExecuteNonQuery();
                }
                /* POTENTIAL FLAW: no check to see whether the user has privileges to view the data */
                IO.WriteString("Bad() - result requested: " + data + "\n");
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error executing query");
            }
            finally
            {
                try
                {
                    if (dBConnection != null)
                    {
                        dBConnection.Close();
                    }
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Could not close Connection");
                }
            }
        }
        catch (SerializationException exceptSerialize)
        {
            IO.Logger.Log(NLog.LogLevel.Warn, "SerializationException in deserialization", exceptSerialize);
        }
    }
#endif
}
}
