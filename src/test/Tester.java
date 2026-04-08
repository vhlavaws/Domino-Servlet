package test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class Tester {
    public static void main(String[] args) throws Exception {
        
        // Log Java environment info on startup
        String version = System.getProperty("java.version");          // e.g., "1.8.0_202"
        String vendor  = System.getProperty("java.vendor");           // e.g., "IBM Corporation"
        String spec    = System.getProperty("java.specification.version"); // e.g., "1.8"
        String vmName  = System.getProperty("java.vm.name");          // e.g., "IBM J9 VM"
        consoleLog("ApiCheckServlet: Starting up with Java "
            + version + " (" + vendor + ", " + vmName + ", spec " + spec + ")");   

        String tcName = "TestTarget1";
        String tcSubType = "TeamViewer";

        String tcApiUrl = "http://webapi.teamviewer.com/api/v1/devices/d1599914075";
        //String tcApiUrl = "https://webapi.teamviewer.com/api/v1/devices/d1599914075";
        String tcHttpMethod = "GET";
        int tcConnectTimeoutSec = 60;
        int tcReadTimeoutSec = 10;
        String tcAuth = "Bearer 123456789abcdef";
        long startTime = System.currentTimeMillis();

        consoleLog("UNIT Tesst ApiCheck: [SYNC] '" + tcName + "' started ");

        
        HttpURLConnection conn = null;
        int apiCode = 0;
        String apiData = null;
        String errorMsg = null;

        try {
            URL url = new URL(tcApiUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(tcHttpMethod);

            // Follows redirects (except for http to https)
            conn.setInstanceFollowRedirects(true);
            conn.setConnectTimeout(tcConnectTimeoutSec * 1000);
            conn.setReadTimeout(tcReadTimeoutSec * 1000);
            
            // Set headers
            conn.setRequestProperty("Authorization", tcAuth);
            conn.setRequestProperty("Accept", "application/json");

            apiCode = conn.getResponseCode();

            // Handle HTTP redirects manually to preserve headers (for http->https case)
            if (apiCode == HttpURLConnection.HTTP_MOVED_TEMP || apiCode == HttpURLConnection.HTTP_MOVED_PERM
                    || apiCode == 307 || apiCode == 308) {

                // Step 2: Get new location
                String newUrl = conn.getHeaderField("Location");
                consoleLog("Redirected to: " + newUrl);

                // Step 3: Close current and open new
                conn.disconnect();

                URL next = new URL(newUrl);
                conn = (HttpURLConnection) next.openConnection();

                conn.setRequestMethod(tcHttpMethod);
                // Step 4: Re-apply security and headers for the HTTPS hop
                if (conn instanceof HttpsURLConnection) {
                    SSLContext sc = SSLContext.getInstance("TLSv1.2");
                    sc.init(null, null, new java.security.SecureRandom());
                    ((HttpsURLConnection) conn).setSSLSocketFactory(sc.getSocketFactory());

                }

                // Follows redirects (except for http to https)
                conn.setInstanceFollowRedirects(true);
                conn.setConnectTimeout(tcConnectTimeoutSec * 1000);
                conn.setReadTimeout(tcReadTimeoutSec * 1000);

                // Set headers
                conn.setRequestProperty("Authorization", tcAuth);
                conn.setRequestProperty("Accept", "application/json");

                apiCode = conn.getResponseCode();
            }


            apiData = readStream(
                (apiCode >= 200 && apiCode < 300)
                    ? conn.getInputStream() : conn.getErrorStream());

            consoleLog("ApiCheckServlet: [SYNC] read response after timeout: " + tcConnectTimeoutSec  + " sec, API code: " + apiCode + ", data length: " + (apiData != null ? apiData.length() : "null"));

        } catch (java.net.SocketTimeoutException e) {
            errorMsg = "timeout: " + e.getMessage();
        } catch (java.net.ConnectException e) {
            errorMsg = "connection_refused: " + e.getMessage();
        } catch (IOException e) {
            errorMsg = "io_error: " + e.getMessage();
        } catch (Exception e) {
            errorMsg = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
          
        }


        long durationMs = System.currentTimeMillis() - startTime;

        // Log result to console
        consoleLog("ApiCheckServlet: [SYNC] '" + tcName
            + "' finished in " + durationMs + "ms"
            + " code=" + apiCode
            + (errorMsg != null ? " error=" + errorMsg : ""));

        // Build response
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"target\":\"").append(escapeJson(tcName)).append("\"");
        json.append(",\"subType\":\"").append(escapeJson(tcSubType)).append("\"");
        json.append(",\"mode\":\"sync\"");
        json.append(",\"durationMs\":").append(durationMs);

        if (errorMsg != null) {
            json.append(",\"status\":\"error\"");
            json.append(",\"error\":\"").append(escapeJson(errorMsg)).append("\"");
        } else {
            json.append(",\"status\":\"ok\"");
            json.append(",\"apiResponseCode\":").append(apiCode);
            json.append(",\"data\":").append(
                apiData != null ? apiData : "null");
        }

       
        json.append(",\"timestamp\":\"").append(utcNow()).append("\"");
        json.append("}");

       consoleLog(json.toString());
        

    }

    /** Log to Domino server console */
    private static void consoleLog(String msg) {
        System.out.println(msg);
    }
    
    /** Read an InputStream to String */
    private static String readStream(InputStream is) throws IOException {
        if (is == null) return null;
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(is, "UTF-8"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }

    
    /** Safe JSON string escape */
    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
        /** Format timestamp to ISO 8601 UTC */
    private static String formatTimestamp(long ts) {
        if (ts == 0) return "never";
        SimpleDateFormat sdf =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date(ts));
    }

    /** Current UTC timestamp as ISO string */
    private static String utcNow() {
        return formatTimestamp(System.currentTimeMillis());
    }
}


