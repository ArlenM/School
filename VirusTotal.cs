using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Malware_Scanner
{
    public class VirusTotal
    {
        public string vt_username = string.Empty;
        public string vt_password = string.Empty;
        private string vt_apikey = string.Empty;
        public string results = string.Empty;
        private string file_name = string.Empty;
        private string file_url = string.Empty;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <param name="pass"></param>
        public VirusTotal(string user, string pass, string key)
        {
            ServicePointManager.Expect100Continue = false;
            this.vt_password = pass;
            this.vt_username = user;
            this.vt_apikey = key;
        }

        /// <summary>
        /// Retrieve a scan report
        /// </summary>
        /// <param name="nResource">the md5 hash of the report</param>
        public void getScanReport(string nResource)
        {
            string r = this.httpPost("https://www.virustotal.com/api/get_file_report.json", "resource=" + nResource + "&key=" + this.vt_apikey);
            JObject o = JObject.Parse(r);
            foreach (JProperty jp in o["report"].Last)
            {
                this.results += jp.Name + "," + jp.First + "\n";
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="nResource"></param>
        /// <param name="autoScan"></param>
        public void getURLScanReport(string nResource, bool autoScan)
        {
            string r = string.Empty;

            if (autoScan)
            {
                r = this.httpPost("https://www.virustotal.com/api/get_url_report.json", "resource=" + nResource + "&key=" + this.vt_apikey + "&scan=1");
            }
            else
            {
                r = this.httpPost("https://www.virustotal.com/api/get_url_report.json", "resource=" + nResource + "&key=" + this.vt_apikey + "&scan=0");
            }

            JObject o = JObject.Parse(r);
            foreach (JProperty jp in o["report"].Last)
            {
                this.results += jp.Name + "," + jp.First + "\n";
            }
        }

        /// <summary>
        /// Send and scan a URL
        /// </summary>
        public void sendAndScanURL(string url, bool autoScan)
        {
            this.file_url = url;
            NameValueCollection nvc = new NameValueCollection();
            nvc.Add("key", this.vt_apikey);
            nvc.Add("url", url);
            if (autoScan) nvc.Add("scan", "1");

            string r = httpPost("https://www.virustotal.com/api/scan_url.json", "url=" + url + "&key=" + this.vt_apikey);

            JObject o = JObject.Parse(r);
            string scan_id = (string)o["scan_id"];
            string[] s = scan_id.Split('-');
            getURLScanReport(s[0], autoScan);
        }

        /// <summary>
        /// Send and scan a file
        /// </summary>
        public void sendAndScanFile(string nFileName)
        {
            this.file_name = nFileName;
            NameValueCollection nvc = new NameValueCollection();
            nvc.Add("key", this.vt_apikey);
            nvc.Add("scan", "1");
            string r = httpUploadFile("https://www.virustotal.com/api/scan_file.json", this.file_name, "file", "application/exe", nvc);

            JObject o = JObject.Parse(r);
            string scan_id = (string)o["scan_id"];
            string[] s = scan_id.Split('-');
            getScanReport(s[0]);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="uri"></param>
        /// <param name="parms"></param>
        /// <returns></returns>
        private string httpPost(string uri, string parms)
        {
            WebRequest req = WebRequest.Create(uri);
            req.Credentials = new NetworkCredential(this.vt_username, this.vt_password);
            req.ContentType = "application/x-www-form-urlencoded";
            req.Method = "POST";
            byte[] bytes = Encoding.ASCII.GetBytes(parms);
            Stream os = null;

            try
            {
                req.ContentLength = bytes.Length;
                os = req.GetRequestStream();
                os.Write(bytes, 0, bytes.Length);
            }
            catch (WebException ex)
            {
                MessageBox.Show(ex.Message, "Request error");
            }
            finally
            {
                if (os != null)
                {
                    os.Close();
                }
            }

            try
            {
                WebResponse webResponse = req.GetResponse();
                if (webResponse == null)
                { return null; }
                StreamReader sr = new StreamReader(webResponse.GetResponseStream());
                return sr.ReadToEnd().Trim();
            }
            catch (WebException ex)
            {
                MessageBox.Show(ex.Message, "Response error");
            }
            return null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="file"></param>
        /// <param name="paramName"></param>
        /// <param name="contentType"></param>
        /// <param name="nvc"></param>
        private string httpUploadFile(string url, string file, string paramName, string contentType, NameValueCollection nvc)
        {
            string ret = string.Empty;

            string boundary = "---------------------------" + DateTime.Now.Ticks.ToString("x");
            byte[] boundarybytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");

            HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(url);
            wr.ContentType = "multipart/form-data; boundary=" + boundary;
            wr.Method = "POST";
            wr.KeepAlive = true;
            wr.Credentials = System.Net.CredentialCache.DefaultCredentials;

            Stream rs = wr.GetRequestStream();
            string formdataTemplate = "Content-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}";

            foreach (string key in nvc.Keys)
            {
                rs.Write(boundarybytes, 0, boundarybytes.Length);
                string formitem = string.Format(formdataTemplate, key, nvc[key]);
                byte[] formitembytes = System.Text.Encoding.UTF8.GetBytes(formitem);
                rs.Write(formitembytes, 0, formitembytes.Length);
            }

            rs.Write(boundarybytes, 0, boundarybytes.Length);
            string headerTemplate = "Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\nContent-Type: {2}\r\n\r\n";
            string header = string.Format(headerTemplate, paramName, file, contentType);
            byte[] headerbytes = System.Text.Encoding.UTF8.GetBytes(header);
            rs.Write(headerbytes, 0, headerbytes.Length);
            FileStream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read);
            byte[] buffer = new byte[4096];
            int bytesRead = 0;

            while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
            {
                rs.Write(buffer, 0, bytesRead);
            }

            fileStream.Close();
            byte[] trailer = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "--\r\n");
            rs.Write(trailer, 0, trailer.Length);
            rs.Close();
            WebResponse wresp = null;

            try
            {
                wresp = wr.GetResponse();
                Stream stream2 = wresp.GetResponseStream();
                StreamReader reader2 = new StreamReader(stream2);
                ret = reader2.ReadToEnd();
            }
            catch (Exception ex)
            {
                if (wresp != null)
                {
                    wresp.Close();
                    wresp = null;
                }
            }
            finally
            {
                wr = null;
            }

            return ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filehash"></param>
        /// <param name="comment"></param>
        /// <param name="tags"></param>
        public void makeCommentOnFile(string hash, string comment, string tags)
        {
            string r = httpPost("https://www.virustotal.com/api/make_comment.json", "file=" + hash + "&comment=" + comment + "&tags=" + tags + "&key=" + this.vt_apikey);

            JObject o = JObject.Parse(r);
            foreach (JProperty jp in o["report"].Last)
            {
                this.results += jp.Name + "," + jp.First + "\n";
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="comment"></param>
        /// <param name="tags"></param>
        public void makeCommentOnURL(string hash, string comment, string tags)
        {
            string r = httpPost("https://www.virustotal.com/api/make_comment.json", "url=" + hash + "&comment=" + comment + "&tags=" + tags + "&key=" + this.vt_apikey);

            JObject o = JObject.Parse(r);
            foreach (JProperty jp in o["result"].Last)
            {
                this.results += jp.Name + "," + jp.First + "\n";
            }
        }
    }
}
