import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lotus.domino.Document;
import lotus.domino.NotesException;
import lotus.domino.NotesThread;

import javax.servlet.ServletException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.servlet.ServletConfig;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * ApiCheckServlet — Multi-target API monitoring servlet for HCL Domino.
 *
 * Reads target configuration from servletconfig.nsf, logs calls to servletlog.nsf, supports
 * per-subtype behavior: - "TeamViewer" subtype: cached/async (returns last known result if API is
 * slow) - All other subtypes: synchronous (waits for actual response or timeout)
 *
 * URL pattern: /servlet/ApiCheck?target=<name>&key=<secret>
 * /servlet/ApiCheck?action=status&key=<secret> — show active calls and cache
 * /servlet/ApiCheck?action=reload&key=<secret> — reload config from DB
 *
 * Deployment: see DEPLOYMENT.md
 */
public class ApiCheckServlet extends HttpServlet {

    // ========================================================================
    // CONFIGURATION CONSTANTS
    // ========================================================================

    /** Default seconds to wait for fresh result on cached subtypes */
    private static final int DEFAULT_CACHE_WAIT_SEC = 21;

    /** Default total seconds for background thread on cached subtypes */
    private static final int DEFAULT_BG_TIMEOUT_SEC = 81;

    /** Default connect timeout in seconds */
    private static final int DEFAULT_CONNECT_TIMEOUT_SEC = 61;

    /** Default read timeout for synchronous subtypes (seconds) */
    private static final int DEFAULT_SYNC_TIMEOUT_SEC = 61;

    /** Max background threads for async API calls */
    private static final int MAX_BG_THREADS = 15;

    /** Secret key for access control */
    private static String secretKey = "SECRET";

    /** Domino server name for NotesFactory (empty = local) */
    private static String dominoServer = "Djangooo";

    /** Config database filename */
    private static String configDb = "tools/servlets_configoo.nsf";

    /** Log database filename */
    private static String logDb = "tools/servlets_configoo.nsf";

    //** Log level */
    private static String logLevel = "WARNING";

    /** Blacklisted IP addresses (regex patterns) */
    private List<Pattern> blockedIpPatterns = new java.util.concurrent.CopyOnWriteArrayList<>();

    // ========================================================================
    // SHARED STATE
    // ========================================================================

    /** Target configurations loaded from config .nsf */
    private static volatile Map<String, TargetConfig> targets = new ConcurrentHashMap<>();

    /** Per-target cached results */
    private static final ConcurrentHashMap<String, CachedResult> cache = new ConcurrentHashMap<>();

    /** Per-target "call in progress" flags */
    private static final ConcurrentHashMap<String, Object> inProgressLocks = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Boolean> inProgress = new ConcurrentHashMap<>();

    /** Global active call counter */
    private static final AtomicInteger activeCallCount = new AtomicInteger(0);

    /** Thread pool for background API calls */
    private static ExecutorService bgExecutor;

    /** Servlet initialization timestamp */
    private static long initTimestamp = 0;

    /** Do not log IP addresses listed here */
    private final Set<String> noLogIps = ConcurrentHashMap.newKeySet();
    

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        consoleLog("ApiCheckServlet: ──────────────────────────────────────────────────────────────────────────────────");
        consoleLog("ApiCheckServlet: Classic Domino HTTP servlet created by VH on 04/2026.");
        consoleLog("ApiCheckServlet: Designed for monitoring external APIs with per-target configuration and logging.");
        consoleLog("ApiCheckServlet: Servlet reads configuration from servlets.properties and configuration database defined in this file.");
      
        // Log Java environment info on startup
        String version = System.getProperty("java.version");
        String vendor = System.getProperty("java.vendor"); 
        String spec = System.getProperty("java.specification.version"); 
        String vmName = System.getProperty("java.vm.name"); 
        consoleLog("ApiCheckServlet: Uses Domino Java " + version + " (" + vendor + ", " + vmName + ", spec "
                + spec + ")");

        consoleLog("ApiCheckServlet: To uninstall:");
        consoleLog("ApiCheckServlet:  - Remove classes files from /data/domino/servlet folder");
        consoleLog("ApiCheckServlet:  - Update /data/servlets.properties file and ");
        consoleLog("ApiCheckServlet:  - Archive config/log databases.");
        consoleLog("ApiCheckServlet: Initializing...");
        
        initTimestamp = System.currentTimeMillis();

        // Get path to config db from init args
        String dbParam = config.getInitParameter("configDbPath");
        if (dbParam != null && dbParam.length() > 0) {
            configDb = dbParam;
        }

        dbParam = config.getInitParameter("logDbPath");
        if (dbParam != null && dbParam.length() > 0) {
            logDb = dbParam;
        }

        String serverParam = config.getInitParameter("dominoServer");
        if (serverParam != null && serverParam.length() > 0) {
            dominoServer = serverParam;
        }

        
        // Create bounded thread pool
        bgExecutor = Executors.newFixedThreadPool(MAX_BG_THREADS);

        // Load configurations from Domino DB
        consoleLog("ApiCheckServlet:  - Reads configuration from database " + configDb + ".");
        reloadConfig();
        consoleLog("ApiCheckServlet:  - Initialized with " + targets.size() + " targets.");
        consoleLog("ApiCheckServlet: ──────────────────────────────────────────────────────────────────────────────────");
    }

    @Override
    public void destroy() {
        consoleLog("ApiCheckServlet: Shutting down...");
        if (bgExecutor != null) {
            bgExecutor.shutdownNow();
        }
        super.destroy();
    }

    // ========================================================================
    // REQUEST HANDLING
    // ========================================================================

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
 
        LogContext ctx = new LogContext();

        response.setContentType("application/json; charset=UTF-8");

        PrintWriter out = response.getWriter();

        // --- Get and validate Request params ---  
        String keyParam = request.getParameter("key");
        String action = request.getParameter("action");
        String targetName = request.getParameter("target");
        consoleLog("ApiCheckServlet: Calling servlet with params - action=" + action + ", target=" + targetName);
        ctx.setRequesContext(action, targetName);

        // Get the IP address
        String ipAddress = getClientIP(request);
        
        // Get the HTTP method (GET, POST, etc.), User-Agent (Browser/Client info), Get the full URL requested
        ctx.setCaller(ipAddress, request.getHeader("User-Agent"), request.getMethod(), request.getRequestURI().toString());

        // --- Auth check ---
        if (keyParam == null || !keyParam.equals(secretKey)) {
            handleNotAuthorized(response, out, ctx);
            return;
        }

        // High-speed check against pre-compiled patterns
        for (Pattern p : blockedIpPatterns) {
            if (p.matcher(ipAddress).matches()) {
                handleNotAuthorizedIP(response, out, ctx);
                return;
            }
        }

        
        // --- Action routing ---
        if ("status".equalsIgnoreCase(action)) {
            handleStatus(response, out, ctx);
            return;
        }
        if ("reload".equalsIgnoreCase(action)) {
            handleReload(response, out, ctx);
            return;
        }

        // Target check 
        if (targetName == null || targetName.length() == 0) {
            response.setStatus(400);
            out.print("{\"error\":\"missing 'target' parameter\"}");
            out.flush();
            return;
        }

        // Target routing: Request comes with params: action=TeamViewerAPIv3&target=d1599914075&key=secret
        // 1. Get configuration based on target match, e.g. "d1599914075" -> "d1599914075" config
        // 2. Failover: Get configuration based on action match: action=TeamViewerAPIv3 -> get "TeamViewerAPIv3" config
        // returns null if no match, so it falls back to 404 error below
        TargetConfig tc = targets.get(targetName.toLowerCase());

        // Failover: Use "action" param as fallback for target lookup (for better compatibility with existing monitoring setups that use "target" param for different instances of the same API type, e.g. multiple TeamViewer accounts)
        if (tc == null) {
            tc = targets.get(action.toLowerCase());
            if ( tc != null ) {
                 tc.apiUrl = tc.apiUrl.replace("{target}", targetName);
                 consoleLog("INFO", "ApiCheckServlet: No direct match for target '" + targetName + "'. Using config for action '" + action + "' as fallback.");
            }       
        }  

        if (tc == null) {              
            response.setStatus(404);
            out.print("{\"error\":\"unknown target: " + escapeJson(targetName) + "\", \"availableTargets\":"
                    + targetListJson() + "}");
            out.flush();
            return;
        }
        
        // --- Dispatch based on subtype ---
       consoleLog("INFO", "ApiCheckServlet: [" + tc.subType + "] " + "Checking target '" + tc.name + "' -> " + tc.apiUrl);
        

        if (tc.useCachedMode) {
            handleCachedTarget(tc, response, out, ctx);
        }
        else {
            handleSyncTarget(tc, response, out, ctx);
        }
    }

    /**
     * Extracts the client's real IP address from the request, accounting for possible proxy headers. 
     * Checks the "X-Forwarded-For" header first (which may contain multiple IPs if there are multiple proxies).
     * Falls back to request.getRemoteAddr() if the header is not present.
     * @param request The HttpServletRequest object containing the client's request information.
     * @return The client's IP address as a String. If multiple IPs are present in "X-Forwarded-For", returns the first one (the original client).
     */
    private String getClientIP(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (clientIp == null || clientIp.isEmpty()) {
            clientIp = request.getRemoteAddr();
        }
        else {
            // If multiple proxies exist, it returns "client, proxy1, proxy2"
            clientIp = clientIp.split(",")[0].trim();
        }
        return clientIp;
    }

    private void handleNotAuthorized(HttpServletResponse response, PrintWriter out, LogContext ctx) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        out.print("{\"error\":\"unauthorized\"}");
        out.flush();

        // Create Notes Log 
        if ((noLogIps.size() >= 100) || noLogIps.contains(ctx.ipAddress)) { 
            // Prevent DoS by too many patterns
            consoleLog("INFO", "Provided secretKey is not valid. Servlet Access denied.");
        } else {
            noLogIps.add(ctx.ipAddress);
            consoleLog("INFO", "Provided secretKey is not valid. Servlet Access denied. IP added to block list: " + ctx.ipAddress);
            ctx.setResult(false, "invalid key");
            ctx.setErrorMsg("Unauthorized access attempt with IP: " + ctx.ipAddress + " and User-Agent: " + ctx.userAgent + "No more logs will be recorded for this IP address");
            // make it final for thread use
            final LogContext finalCtx = ctx;
            logCallAsync(finalCtx);
        }
    }

    private void handleNotAuthorizedIP(HttpServletResponse response, PrintWriter out, LogContext ctx) {
      // response.sendError(HttpServletResponse.SC_FORBIDDEN, "{\"error\":\"IP " + clientIp + " blocked\"}");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        out.print("{\"error\":\"unauthorized\"}");
        out.flush();

        // Create Notes Log 
        if ((noLogIps.size() >= 100) || noLogIps.contains(ctx.ipAddress)) { 
            // Prevent DoS by too many patterns
            consoleLog("INFO", "Client IP is blocked: " + ctx.ipAddress + ". Servlet Access denied."); ;
            
        } else {
            noLogIps.add(ctx.ipAddress);
            consoleLog("INFO", "Client IP is blocked: " + ctx.ipAddress + ". Servlet Access denied. IP added to block list: " + ctx.ipAddress);
            ctx.setErrorMsg("Client IP: " + ctx.ipAddress + " is blocked. No more logs will be recorded for this IP address");
            ctx.setResult(false, "Blocked IP");
            
            // make logContext final for thread use
            final LogContext finalCtx = ctx;
            logCallAsync(finalCtx);
        }
    }

    // ========================================================================
    // SYNCHRONOUS TARGET HANDLING (Viber, ProfiSMS, Sametime, etc.)
    // ========================================================================
    /**
     * Calls the API synchronously — waits for response or timeout. Returns the actual live result to
     * the monitoring app.
     */
    private void handleSyncTarget(TargetConfig tc, HttpServletResponse response, PrintWriter out, LogContext ctx) {

        int active = activeCallCount.incrementAndGet();
        long startTime = System.currentTimeMillis();
        
        consoleLog("INFO", "ApiCheckServlet: [SYNC] '" + tc.name + "' started (active calls: " + active + ")");
        
        HttpURLConnection conn = null;
        int apiCode = 0;
        String apiData = null;
        String errorMsg = null;

        try {
            URL url = new URL(tc.apiUrl);
            conn = (HttpURLConnection) url.openConnection();

            if (conn instanceof HttpsURLConnection) {
                SSLContext sc = SSLContext.getInstance("TLSv1.2");
                sc.init(null, null, new java.security.SecureRandom());
                ((HttpsURLConnection) conn).setSSLSocketFactory(sc.getSocketFactory());
                consoleLog("INFO", "ApiCheckServlet: [SYNC] '" + tc.name + "' using HTTPS with TLSv1.2");
            }
            setRequestProperties(conn, tc);
            apiCode = conn.getResponseCode();

            // Handle HTTP redirects manually to preserve headers (for http->https case)
            if (apiCode == HttpURLConnection.HTTP_MOVED_TEMP || apiCode == HttpURLConnection.HTTP_MOVED_PERM
                    || apiCode == 307 || apiCode == 308) {

                // Get new location
                String newUrl = conn.getHeaderField("Location");
                consoleLog("INFO", "ApiCheckServlet: [SYNC] '" + tc.name + "' Redirected to: " + newUrl);

                // Close current and open new
                conn.disconnect();

                URL next = new URL(newUrl);
                conn = (HttpURLConnection) next.openConnection();

                if (conn instanceof HttpsURLConnection) {
                    SSLContext sc = SSLContext.getInstance("TLSv1.2");
                    sc.init(null, null, new java.security.SecureRandom());
                    ((HttpsURLConnection) conn).setSSLSocketFactory(sc.getSocketFactory());
                    consoleLog("INFO", "ApiCheckServlet: [SYNC] '" + tc.name + "' using HTTPS with TLSv1.2 after redirect");
                }

                // Re-apply timeouts, method, and headers for the new connection, 
                // TODO: timeouts should ideally be subtracted by the time already spent on the first call
                setRequestProperties(conn, tc);

                apiCode = conn.getResponseCode();
            }

            apiData = readStream((apiCode >= 200 && apiCode < 300) ? conn.getInputStream() : conn.getErrorStream());
            consoleLog("INFO", "ApiCheckServlet: [SYNC] response code: " + apiCode + ", data length: " + (apiData != null ? apiData.length() : "null"));
            
        } catch (java.net.SocketTimeoutException e) {
            consoleLog("timeout: " + e.getMessage());
            errorMsg = "timeout: " + e.getMessage();
            apiData = "{\"error\": \"" + e.getLocalizedMessage() + "\"}";
        } catch (java.net.ConnectException e) {   
            errorMsg = "connection_refused: " + e.getMessage();
            apiData = "{\"error\": \"" + e.getLocalizedMessage() + "\"}";
        } catch (IOException e) {  
            errorMsg = "io_error: " + e.getMessage();
            apiData = "{\"error\": \"" + e.getLocalizedMessage() + "\"}";
        } catch (Exception e) {
            errorMsg = e.getClass().getSimpleName() + ": " + e.getMessage();
            apiData = "{\"error\": \"" + e.getLocalizedMessage() + "\"}";
        } finally {
            
            if (conn != null) {
                conn.disconnect();
            }
            activeCallCount.decrementAndGet();
        }

        if (apiData == null) {
            consoleLog("INFO", "ApiCheckServlet: [SYNC] '" + tc.name + "' API call finished with code " + apiCode
                    + (errorMsg != null ? " and error: " + errorMsg : ""));
            apiData = "{error}";
        }
        // Update log context
        ctx.setTarget(tc.name, tc.apiUrl, tc.httpMethod, tc.subType, "SYNC")
           .setResults(apiCode, errorMsg, apiData);
            
        // Build response by API type (each api has specific response format, return raw data and code for now)
        buildApiResponse(tc, response, out, ctx);  
        out.flush();
        ctx.setResult((errorMsg == null || errorMsg.length() == 0)? true : false, ctx.result);

        // Log to a log database asynchronously to avoid slowing down the response.
        final LogContext finalCtx = ctx;
        logCallAsync(finalCtx);

        long durationMs = System.currentTimeMillis() - startTime;
        consoleLog("ApiCheckServlet: [SYNC] '" + tc.name + "' finished in " + durationMs + " ms" + " code=" + apiCode
                + (errorMsg != null ? " error=" + errorMsg : ""));
    }

    // ========================================================================
    // CACHED TARGET HANDLING (TeamViewer — slow API)
    // ========================================================================

    private void buildApiResponse(TargetConfig tc, HttpServletResponse response, PrintWriter out, LogContext ctx) {
       
        // get used memory
        Runtime runtime = Runtime.getRuntime();
        // long maxMemory = runtime.maxMemory();        // -Xmx (Maximum possible heap)
        long allocatedMemory = runtime.totalMemory();   // Current heap size (can grow up to max)
        long freeMemory = runtime.freeMemory();         // Free space WITHIN the allocated heap   
        long usedMemory = allocatedMemory - freeMemory; // The actual memory used by objects

        // Set common response headers
        response.setStatus(200);
        // Set content type and caching headers
        response.setContentType("application/json; charset=UTF-8");
        // Prevent caching for HTTP 1.1
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate"); 
        // Prevent caching for HTTP 1.0 (Legacy support)
        response.setHeader("Pragma", "no-cache"); 
        // Proxies/older caches
        response.setDateHeader("Expires", 0);

        StringBuilder json;
        
        switch (tc.subType) {
        case "TeamViewer":
        case "TeamViewerAPI for PRTG REST Custom V2":
            json = buildTeamViewerResponseV2(ctx, usedMemory);  
            break;
        case "TeamViewerAPI for PRTG REST JSON DATA":
            json = buildTeamViewerResponseV3(tc, ctx,  usedMemory);  
            break;
        default:
            json = new StringBuilder();
            json.append("{");
            json.append("\"target\":\"").append(escapeJson(tc.name)).append("\"");
            json.append(",\"subType\":\"").append(escapeJson(tc.subType)).append("\"");
            json.append(",\"mode\":\"sync\"");
            json.append(",\"durationMs\":").append(ctx.getDurationMs());
            json.append(",\"JVM used memory\":").append(usedMemory);

            if (ctx.errorMsg != null) {
                json.append(",\"status\":\"error\"");
                json.append(",\"error\":\"").append(escapeJson(ctx.errorMsg)).append("\"");
            }
            else {
                json.append(",\"status\":\"ok\"");
                json.append(",\"apiResponseCode\":").append(ctx.httpCode);
                json.append(",\"data\":").append(ctx.apiData != null ? ctx.apiData : "null");
            }

            json.append(",\"activeCalls\":").append(activeCallCount.get());
            json.append(",\"timestamp\":\"").append(utcNow()).append("\"");
            json.append("}");
        }

        try {
            response.setContentLength(json.toString().getBytes("UTF-8").length);
        } catch (UnsupportedEncodingException e) {
            consoleLog("ApiCheckServlet: [WARN] UTF-8 encoding not supported, cannot set content length");
        }   
        out.print(json.toString());
    }

    private StringBuilder buildTeamViewerResponseV2(LogContext ctx, long usedMemory) {
       
        StringBuilder json = new StringBuilder();

        // Regex logic: Find "online_state" and capture the value between quotes
        // \"online_state\"\s*:\s*\"([^\"]*)\"
        // 1. Match the key "online_state"
        // 2. \s*:\s* handles potential whitespace around the colon
        // 3. \"([^\"]*)\" captures everything inside the following quotes
        Pattern pattern = Pattern.compile("\"online_state\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(ctx.apiData);
        String device_status = "Unknown";
        if (matcher.find()) {
           device_status = matcher.group(1);
        }

        // Regex logic to extract teamviewer_id
        pattern = Pattern.compile("\"teamviewer_id\"\\s*:\\s*(\\d+)");
        matcher = pattern.matcher(ctx.apiData);
        String tv_Id = "-1";
        if (matcher.find()) {
            tv_Id = matcher.group(1);
        }

        json.append("{").append("\"prtg\":{");
            json.append("\"result\":[")
                .append("{\"channel\":\"Status\",\"value\":")
                .append(device_status.equals("Online") ? "1" : "0").append("},")
                .append("{\"channel\":\"TeamViewerID\",\"value\":")
                .append(tv_Id).append("},")
                .append("{\"channel\":\"ResponseTime\",\"value\":")
                .append(ctx.getDurationMs()).append("},")
                .append("{\"channel\":\"JVM used memory\",\"value\":")
                .append(usedMemory).append("}")
                .append("]}}");   
        return json; 
    }

   private StringBuilder buildTeamViewerResponseV3(TargetConfig tc, LogContext ctx, long usedMemory) {
        StringBuilder json = new StringBuilder();

        // Regex logic: Find "online_state" and capture the value between quotes
        // \"online_state\"\s*:\s*\"([^\"]*)\"
        // 1. Match the key "online_state"
        // 2. \s*:\s* handles potential whitespace around the colon
        // 3. \"([^\"]*)\" captures everything inside the following quotes
        Pattern pattern = Pattern.compile("\"online_state\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(ctx.apiData);
        String device_status = "Unknown";
        String senzorMsg = "TV ID: Unknown";
        if (matcher.find()) {
           device_status = matcher.group(1);
        }

        // Regex logic to extract teamviewer_id
        pattern = Pattern.compile("\"teamviewer_id\"\\s*:\\s*(\\d+)");
        matcher = pattern.matcher(ctx.apiData);
        String tv_Id = "-1";
        if (matcher.find()) {
            tv_Id = matcher.group(1);
            senzorMsg = "TV ID: " + tv_Id;
        }

        // Status PRTG Statuses: Up status: ok, warning status: warning, Down status: error, Unknown status: warning
        String statusString = "warning";
        switch (device_status) {
            case "Online":
                statusString = (ctx.getDurationMs() > 5000) ? "warning" : "ok";
                senzorMsg = senzorMsg + " is Online" + ((ctx.getDurationMs() > 5000) ? ", but slow": "");
                break;
            case "Offline":
                statusString = "error";
                senzorMsg = senzorMsg + " is Offline.";
                break;
            case "Unknown":
                statusString = "warning";
                senzorMsg = senzorMsg + " is Unknown.";
                break;
            default:
                statusString = "warning";
                senzorMsg = senzorMsg + " Status: " + device_status;
                 break;
        }
        
        json.append("{")
                .append("\"version\":3,")
                .append("\"status\":\"").append(statusString).append("\",")
                .append("\"message\":\"").append(senzorMsg).append("\",")
                .append("\"channels\":[")
                    .append("{\"id\":10,")
                    .append("\"name\":\"Availability\",");

        // If a lookup name is provided in the config, use "lookup" type with that name. Otherwise, default to "integer" type with "custom" kind.
        if (tc.prtg_LookupName != null && tc.prtg_LookupName.length() > 0) {
                json.append("\"type\": \"lookup\",")
                    .append("\"lookup_name\":\"").append(escapeJson(tc.prtg_LookupName)).append("\",");
        } else {
                json.append("\"type\":\"integer\",")
                    .append("\"kind\":\"custom\",");
        }
                json.append("\"value\":").append(device_status.equals("Online") ? "1" : "0").append("},")
        
                    .append("{\"id\":11,")
                    .append("\"name\":\"Response Time\",")
                    .append("\"type\":\"float\",")
                    .append("\"kind\":\"time_milliseconds\",")
                    .append("\"value\":").append(ctx.getDurationMs()).append("},")

                    .append("{\"id\":12,")
                    .append("\"name\":\"JVM Heap Memory\",")
                    .append("\"type\":\"float\",")
                    .append("\"kind\":\"size_bytes_memory\",")
                    .append("\"value\":").append(usedMemory).append("},")

                    .append("{\"id\":13,")
                    .append("\"name\":\"TeamViewerID\",")
                    .append("\"type\":\"float\",")
                    .append("\"kind\":\"custom\",")
                    .append("\"value\":").append(tv_Id).append(",")
                    .append("\"display_unit\":\"\"").append("}")
                .append("]}");
        return json;  
    }

    private void setRequestProperties(HttpURLConnection conn, TargetConfig tc) throws Exception {
        conn.setRequestMethod(tc.httpMethod);
        conn.setConnectTimeout((tc.connectTimeoutSec * 1000) + 100);
        conn.setReadTimeout((tc.readTimeoutSec * 1000) + 100);

        // Set headers
        if (tc.authHeader != null && tc.authHeader.length() > 0) {
            conn.setRequestProperty("Authorization", tc.authHeader);
        }
        conn.setRequestProperty("Accept", "application/json");

        // Add custom headers from config
        if (tc.customHeaders != null) {
            for (Map.Entry<String, String> h : tc.customHeaders.entrySet()) {
                conn.setRequestProperty(h.getKey(), h.getValue());
            }
        }
    }

    /**
     * For slow APIs: start background call, wait up to N seconds for fresh result. If not ready, return
     * last cached result. Background thread continues until API responds or total timeout.
     */
    private void handleCachedTarget(TargetConfig tc, HttpServletResponse response, PrintWriter out, LogContext ctx) {

        //TODO - REFACTOR AND IMPLEMENT AND TEST
        String key = tc.name.toLowerCase();

        // Ensure lock object exists for this target
        inProgressLocks.putIfAbsent(key, new Object());
        Object lock = inProgressLocks.get(key);

        // Start background call if not already running
        boolean startedNew = false;
        synchronized (lock) {
            Boolean running = inProgress.get(key);
            if (running == null || !running) {
                inProgress.put(key, Boolean.TRUE);
                startedNew = true;
                bgExecutor.submit(new BackgroundApiCaller(tc, key, lock));
            }
        }

        // Wait up to cacheWaitSec for fresh result
        long waitUntil = System.currentTimeMillis() + (tc.cacheWaitSec * 1000L);
        synchronized (lock) {
            while (Boolean.TRUE.equals(inProgress.get(key)) && System.currentTimeMillis() < waitUntil) {
                try {
                    long remaining = waitUntil - System.currentTimeMillis();
                    if (remaining > 0) {
                        lock.wait(remaining);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        

        // Build response from cache
        CachedResult cr = cache.get(key);
        boolean bgRunning;
        synchronized (lock) {
            bgRunning = Boolean.TRUE.equals(inProgress.get(key));
        }

        response.setStatus(200);
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"target\":\"").append(escapeJson(tc.name)).append("\"");
        json.append(",\"subType\":\"").append(escapeJson(tc.subType)).append("\"");
        json.append(",\"mode\":\"cached\"");
        json.append(",\"bgRunning\":").append(bgRunning);

        if (cr == null) {
            json.append(",\"status\":\"no_data_yet\"");
            json.append(",\"message\":\"First call in progress, " + "no cached result available\"");
        }
        else {
            long ageSeconds = (System.currentTimeMillis() - cr.timestamp) / 1000;
            boolean isFresh = (ageSeconds < 30);

            json.append(",\"status\":\"").append(isFresh ? "fresh" : "cached").append("\"");
            json.append(",\"ageSeconds\":").append(ageSeconds);
            json.append(",\"lastUpdate\":\"").append(formatTimestamp(cr.timestamp)).append("\"");
            json.append(",\"lastDurationMs\":").append(cr.durationMs);

            if (cr.errorMsg != null) {
                json.append(",\"lastError\":\"").append(escapeJson(cr.errorMsg)).append("\"");
            }
            else {
                json.append(",\"apiResponseCode\":").append(cr.httpCode);
                json.append(",\"data\":").append(cr.data != null ? cr.data : "null");
            }
        }

        json.append(",\"activeCalls\":").append(activeCallCount.get());
        json.append(",\"timestamp\":\"").append(utcNow()).append("\"");
        json.append("}");

        out.print(json.toString());
        out.flush();
    }

    // ========================================================================
    // BACKGROUND API CALLER (for cached subtypes)
    // ========================================================================
    /**
     * Runs in the background thread pool. Calls the slow API, updates cache when done, notifies waiting
     * thread.
     */
    private class BackgroundApiCaller implements Runnable {
        private final TargetConfig tc;
        private final String cacheKey;
        private final Object lock;

        BackgroundApiCaller(TargetConfig tc, String cacheKey, Object lock) {
            this.tc = tc;
            this.cacheKey = cacheKey;
            this.lock = lock;
        }

        @Override
        public void run() {
            int active = activeCallCount.incrementAndGet();
            long startTime = System.currentTimeMillis();

            consoleLog(
                    "ApiCheckServlet: [CACHED-BG] '" + tc.name + "' background call started (active: " + active + ")");

            HttpURLConnection conn = null;
            int apiCode = 0;
            String apiData = null;
            String errorMsg = null;

            try {
                URL url = new URL(tc.apiUrl);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod(tc.httpMethod);
                conn.setConnectTimeout(tc.connectTimeoutSec * 1000);
                conn.setReadTimeout(tc.bgTimeoutSec * 1000);

                if (tc.authHeader != null && tc.authHeader.length() > 0) {
                    conn.setRequestProperty("Authorization", tc.authHeader);
                }
                conn.setRequestProperty("Accept", "application/json");

                if (tc.customHeaders != null) {
                    for (Map.Entry<String, String> h : tc.customHeaders.entrySet()) {
                        conn.setRequestProperty(h.getKey(), h.getValue());
                    }
                }

                apiCode = conn.getResponseCode();
                apiData = readStream((apiCode >= 200 && apiCode < 300) ? conn.getInputStream() : conn.getErrorStream());

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
                activeCallCount.decrementAndGet();
            }

            LogContext ctx = new LogContext();
            ctx.setCaller("BackgroundThread", "N/A", tc.httpMethod, tc.apiUrl);
            ctx.setTarget(tc.name, tc.apiUrl, tc.httpMethod, tc.subType, "CACHED-BG");
               
            long durationMs = System.currentTimeMillis() - startTime;

            // Update cache
            CachedResult cr = new CachedResult();
            cr.httpCode = apiCode;
            cr.data = apiData;
            cr.errorMsg = errorMsg;
            cr.durationMs = durationMs;
            cr.timestamp = System.currentTimeMillis();
            cache.put(cacheKey, cr);

            // Log
            logCallAsync(ctx);

            consoleLog("ApiCheckServlet: [CACHED-BG] '" + tc.name + "' finished in " + durationMs + "ms" + " code="
                    + apiCode + (errorMsg != null ? " error=" + errorMsg : ""));

            // Signal waiting servlet thread
            synchronized (lock) {
                inProgress.put(cacheKey, Boolean.FALSE);
                lock.notifyAll();
            }
        }
    }

    // ========================================================================
    // STATUS & RELOAD ACTIONS
    // ========================================================================

    private void handleStatus(HttpServletResponse response, PrintWriter out, LogContext ctx) {
        response.setStatus(200);
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"servletUpSince\":\"").append(formatTimestamp(initTimestamp)).append("\"");
        json.append(",\"uptimeMinutes\":").append((System.currentTimeMillis() - initTimestamp) / 60_000);
        json.append(",\"activeCalls\":").append(activeCallCount.get());
        json.append(",\"configuredTargets\":").append(targets.size());
        json.append(",\"maxBgThreads\":").append(MAX_BG_THREADS);
       
        // Per-target cache status
        json.append(",\"targets\":[");
        boolean first = true;
        for (Map.Entry<String, TargetConfig> entry : targets.entrySet()) {
            if (!first)
                json.append(",");
            first = false;
            TargetConfig tc = entry.getValue();
            CachedResult cr = cache.get(entry.getKey());
            Boolean running = inProgress.get(entry.getKey());

            json.append("{\"name\":\"").append(escapeJson(tc.name)).append("\"");
            json.append(",\"apiSubType\":\"").append(escapeJson(tc.subType)).append("\"");
            json.append(",\"mode\":\"").append(tc.useCachedMode ? "cached" : "sync").append("\"");
            json.append(",\"timeout\":").append(tc.connectTimeoutSec + tc.readTimeoutSec);
            json.append(",\"bgRunning\":").append(Boolean.TRUE.equals(running));
            if (cr != null) {
                long age = (System.currentTimeMillis() - cr.timestamp) / 1000;
                json.append(",\"lastUpdate\":\"").append(formatTimestamp(cr.timestamp)).append("\"");
                json.append(",\"ageSeconds\":").append(age);
                json.append(",\"lastCode\":").append(cr.httpCode);
                json.append(",\"lastDurationMs\":").append(cr.durationMs);
                if (cr.errorMsg != null) {
                    json.append(",\"lastError\":\"").append(escapeJson(cr.errorMsg)).append("\"");
                }
            }
            else {
                json.append(",\"lastUpdate\":\"never\"");
            }
            json.append("}");
        }
        json.append("]");

        // Blocked IP patterns
        json.append(",\"blockedIpPatterns\":[");
        first = true;
        for (Pattern p : blockedIpPatterns) {
            if (!first)
                json.append(",");
            first = false;
            json.append("\"").append(escapeJson(p.pattern())).append("\"");
        }
        if (first) {json.append("\"none\"");};
        json.append("]");
        json.append("}");

        out.print(json.toString());
        out.flush();

        ctx.setTarget("APICheckServlet", "N/A", "N/A", "Status", "0")
            .setResults(200, "",json.toString())
            .setResult(true, "Show servlet status");

        // make it final for thread use
        final LogContext finalCtx = ctx;
        logCallAsync(finalCtx);
    }

    private void handleReload(HttpServletResponse response, PrintWriter out, LogContext ctx) {
        consoleLog("ApiCheckServlet: Reloading configuration...");
        int count = reloadConfig();
        consoleLog("ApiCheckServlet: Reloaded " + count + " targets.");

        response.setStatus(200);
        out.print("{\"status\":\"ok\",\"targetsLoaded\":" + count + "}");
        out.flush();

        ctx.setTarget("APICheckServlet", "N/A", "N/A", "Reload", "0");
        ctx.setResults(200, "", "Reloaded " + count + " targets.");
        ctx.setResult(true, "Reload servlet configuration");

        // make it final for thread use
        final LogContext finalCtx = ctx;
        logCallAsync(finalCtx);
    }

    // ========================================================================
    // CONFIG LOADER — reads from servletconfig.nsf
    // ========================================================================

    private int reloadConfig() {
        Map<String, TargetConfig> newTargets = new ConcurrentHashMap<>();

        lotus.domino.Session session = null;
        lotus.domino.Database db = null;
        lotus.domino.View view = null;

        try {
            NotesThread.sinitThread();
            session = lotus.domino.NotesFactory.createSession();
            db = session.getDatabase(dominoServer, configDb, false);

            if (db == null || !db.isOpen()) {
                consoleLog("ApiCheckServlet: ERROR — Cannot open " + configDb);
                return 0;
            }

            lotus.domino.Document profile = db.getProfileDocument("Profile", null);
            String logLevelParam = getItemString(profile, "LogLevel");
            if (logLevelParam != null && logLevelParam.length() > 0) {
                logLevel = logLevelParam;
            }

            String keyParam = getItemString(profile, "SecretKey");
            if (keyParam != null && keyParam.length() > 0) {  
                secretKey = keyParam;
                consoleLog("INFO","Servlet secret key initialized from config's database profile.");
            } 

            loadBlockeIPList(profile);
            recycleQuietly(profile);
            
            view = db.getView("($APIChecksActiveTargets)");
            if (view == null) {
                consoleLog("ApiCheckServlet: ERROR — View '($APIChecksActiveTargets)' " + "not found in " + configDb);
                return 0;
            }

            view.setAutoUpdate(false);
            lotus.domino.Document doc = view.getFirstDocument();

            while (doc != null) {
                try {
                    TargetConfig tc = new TargetConfig();
                    tc.name = getItemString(doc, "TargetName");
                    tc.subType = getItemString(doc, "SubType");
                    tc.apiUrl = getItemString(doc, "ApiUrl");
                    tc.httpMethod = getItemString(doc, "HttpMethod");
                    tc.authHeader = getItemString(doc, "AuthHeader");
                    tc.prtg_LookupName = getItemString(doc, "PRTG_Availability_LookupName");

                    if (tc.httpMethod == null || tc.httpMethod.length() == 0) {
                        tc.httpMethod = "GET";
                    }

                    // Timeouts
                    tc.connectTimeoutSec = getItemInt(doc, "ConnectTimeoutSec", DEFAULT_CONNECT_TIMEOUT_SEC);
                    tc.readTimeoutSec = getItemInt(doc, "ReadTimeoutSec", DEFAULT_SYNC_TIMEOUT_SEC);
                    tc.cacheWaitSec = getItemInt(doc, "CacheWaitSec", DEFAULT_CACHE_WAIT_SEC);
                    tc.bgTimeoutSec = getItemInt(doc, "BgTimeoutSec", DEFAULT_BG_TIMEOUT_SEC);

                    // Cached mode — from config or auto-detect by subtype
                    String cachedFlag = getItemString(doc, "UseCachedMode");
                    if ("1".equals(cachedFlag) || "Yes".equalsIgnoreCase(cachedFlag)) {
                        tc.useCachedMode = true;
                    }
                    else {
                        tc.useCachedMode = false;
                    }

                    // Custom headers (multi-value field: "Header-Name: value")
                    java.util.Vector<?> headers = doc.getItemValue("CustomHeaders");
                    if (headers != null && headers.size() > 0) {
                        tc.customHeaders = new java.util.LinkedHashMap<>();
                        for (Object h : headers) {
                            String hs = h.toString().trim();
                            int colon = hs.indexOf(':');
                            if (colon > 0) {
                                tc.customHeaders.put(hs.substring(0, colon).trim(), hs.substring(colon + 1).trim());
                            }
                        }
                    }

                    if (tc.name != null && tc.name.length() > 0 && tc.apiUrl != null && tc.apiUrl.length() > 0) {
                        newTargets.put(tc.name.toLowerCase(), tc);
                        consoleLog("INFO", "ApiCheckServlet: Loaded target '" + tc.name + "' [" + tc.subType + "] "
                                + (tc.useCachedMode ? "CACHED" : "SYNC"));
                    }

                } catch (Exception e) {
                    consoleLog("ApiCheckServlet: Error reading config doc: " + e.getMessage());
                }

                lotus.domino.Document next = view.getNextDocument(doc);
                doc.recycle();
                doc = next;
            }
        } catch (lotus.domino.NotesException ne) {
            consoleLog("ApiCheckServlet: ERROR loading config: " + ne.getMessage());
        } catch (Exception e) {
            consoleLog("ApiCheckServlet: ERROR loading config: " + e.getMessage());
        } finally {
            recycleQuietly(view);
            recycleQuietly(db);
            recycleQuietly(session);
            NotesThread.stermThread(); // deregister — always runs, even on exception
        }

        targets = newTargets;
        return newTargets.size();
    }

    private void loadBlockeIPList(Document profile) throws NotesException {
        Vector<?> rawValues = profile.getItemValue("IPs_Blocked");

        // Create a temporary local list to avoid partial updates to the shared list
        List<Pattern> newList = new java.util.ArrayList<>();
        for (Object val : rawValues) {
            String entry = (val != null) ? val.toString().trim() : "";
            if (entry.isEmpty())
                continue;

            // Handle potential comma-separated values within a single Vector element
            String[] parts = entry.split(",");
            for (String part : parts) {
                try {
                    // Compile once and store in memory
                    newList.add(Pattern.compile(part.trim()));
                } catch (PatternSyntaxException e) {
                    consoleLog("ApiCheckServlet: [WARN] - Invalid Regex ignored: " + part);
                }
            }
        }

        // Atomic update: replaces the reference so active doGet threads aren't interrupted
        this.blockedIpPatterns = new java.util.concurrent.CopyOnWriteArrayList<>(newList);
    }

    // ========================================================================
    // LOGGER — writes to servletlog.nsf (async to not block response)
    // ========================================================================
    private void logCallAsync(final LogContext ctx) {
        bgExecutor.submit(new Runnable() {
            @Override
            public void run() {
                logCall(ctx);
            }
        });
    }

    private void logCall(final LogContext ctx) {
        lotus.domino.Session session = null;
        lotus.domino.Database db = null;
        lotus.domino.Document doc = null;
        lotus.domino.DateTime dt = null; 
        try {
            NotesThread.sinitThread();
            session = lotus.domino.NotesFactory.createSession();
            db = session.getDatabase(dominoServer, logDb, false);

            if (db == null || !db.isOpen()) {
                consoleLog("ApiCheckServlet: WARNING — Cannot open " + logDb + " for logging");
                return;
            }

            doc = db.createDocument();
            doc.replaceItemValue("Form", "ApiCallLog");

             // Convert the final startTime to a NotesDateTime in THIS thread
            dt = session.createDateTime(new java.util.Date(ctx.startTime));
            doc.replaceItemValue("CallTimestamp", dt);

            doc.replaceItemValue("TargetName", ctx.targetName);
            doc.replaceItemValue("ApiSubType", ctx.targetApiVersion);
            doc.replaceItemValue("ApiUrl", ctx.targetApiUrl);
            doc.replaceItemValue("Mode", ctx.mode);

            doc.replaceItemValue("Caller_UserAgent", ctx.userAgent);
            doc.replaceItemValue("Caller_IPAddress", ctx.ipAddress);
            doc.replaceItemValue("Caller_Method", ctx.httpMethod);
            doc.replaceItemValue("Action", ctx.action);
            
            doc.replaceItemValue("HttpCode", ctx.httpCode);
            doc.replaceItemValue("DurationMs", System.currentTimeMillis() - ctx.startTime);
            
            doc.replaceItemValue("ProcessedTimestamp", session.createDateTime(new Date()));
            doc.replaceItemValue("ApiPayload", ctx.apiData != null ? ctx.apiData : ""); 
           
            if (ctx.isCachedResponseUsed) {
                doc.replaceItemValue("CachedResponseUsed", "1");
                if (ctx.cacheResponseTime > 0) {
                    dt = session.createDateTime(new java.util.Date(ctx.cacheResponseTime));
                    doc.replaceItemValue("CacheResponseTimestamp", dt);
                }
            }

            doc.replaceItemValue("ActiveCalls", activeCallCount.get());

            if (ctx.errorMsg != null && ctx.errorMsg.length() > 0) {
                doc.replaceItemValue("ErrorMsg", ctx.errorMsg);
                doc.replaceItemValue("Success", "0");
            }
            else {
                doc.replaceItemValue("ErrorMsg", "");
                doc.replaceItemValue("Success", "1");
            }
            doc.replaceItemValue("Result", ctx.result );

            doc.save(true, false);

        } catch (Exception e) {
            consoleLog("ApiCheckServlet: WARNING — Log write failed: " + e.getMessage());
        } finally {
            recycleQuietly(dt);
            recycleQuietly(doc);
            recycleQuietly(db);
            recycleQuietly(session);
            NotesThread.stermThread(); // deregister — always runs, even on exception
        }
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /** Log to Domino server console */
    private static void consoleLog(String msg) {
        System.out.println(msg);
    }
    private static void consoleLog(String level, String msg) {
        if (logLevel.equals("INFO") || level.equals("WARNING")) {
            System.out.println( msg);
        }
    }

    /** Read an InputStream to String */
    private static String readStream(InputStream is) throws IOException {
        if (is == null)
            return null;
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }

    /** Safe JSON string escape */
    private static String escapeJson(String s) {
        if (s == null)
            return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t",
                "\\t");
    }

    /** Format timestamp to ISO 8601 UTC */
    private static String formatTimestamp(long ts) {
        if (ts == 0)
            return "never";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date(ts));
    }

    /** Current UTC timestamp as ISO string */
    private static String utcNow() {
        return formatTimestamp(System.currentTimeMillis());
    }

    /** Get string item from Notes document, null-safe */
    private static String getItemString(lotus.domino.Document doc, String itemName) {
        try {
            String val = doc.getItemValueString(itemName);
            return (val != null && val.length() > 0) ? val.trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Get integer item from Notes document with default */
    private static int getItemInt(lotus.domino.Document doc, String itemName, int defaultVal) {
        try {
            return doc.getItemValueInteger(itemName);
        } catch (Exception e) {
            // ignore parse errors
        }
        return defaultVal;
    }


    /** Build JSON array of target names */
    private String targetListJson() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (TargetConfig tc : targets.values()) {
            if (!first)
                sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(tc.name)).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    /** Safe recycle for Domino objects */
    private static void recycleQuietly(lotus.domino.Base obj) {
        if (obj != null) {
            try {
                obj.recycle();
            } catch (Exception e) {
                /* ignore */ }
        }
    }
}
