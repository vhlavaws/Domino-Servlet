import java.util.Map;

/**
 * Configuration for a single monitoring target.
 * Loaded from servletconfig.nsf.
 */
public class TargetConfig {

    /** Display name / identifier (e.g. "TeamViewerProd") */
    public String name;

    /**
     * Subtype determines behavior category:
     *   "TeamViewer"  — slow API, uses cached/async mode
     *   "ViberAPI"    — synchronous
     *   "ProfiSMSAPI" — synchronous
     *   "SametimeAPI" — synchronous
     *   (any other)   — synchronous by default
     */
    public String subType;

    /** Full API endpoint URL */
    public String apiUrl;

    /** HTTP method: GET, POST, etc. Default: GET */
    public String httpMethod = "GET";

    /** Authorization header value (e.g. "Bearer xxx" or "Basic xxx") */
    public String authHeader;

    /** Additional HTTP headers: key=header name, value=header value */
    public Map<String, String> customHeaders;

    /** Specific properties for each target type */
    public String prtg_LookupName = "";

    /** TCP connect timeout in seconds */
    public int connectTimeoutSec = 60;

    /** Read timeout for synchronous mode (seconds) */
    public int readTimeoutSec = 60;

    /**
     * Whether to use cached/async mode:
     *  true  = return last cached result if API doesn't respond in cacheWaitSec
     *  false = wait for full response or timeout (synchronous)
     */
    public boolean useCachedMode = false;

    /** Seconds to wait for fresh result before returning cache (cached mode) */
    public int cacheWaitSec = 20;

    /** Total seconds for background API call (cached mode) */
    public int bgTimeoutSec = 80;

    @Override
    public String toString() {
        return "TargetConfig{name='" + name + "', subType='" + subType
            + "', url='" + apiUrl + "', cached=" + useCachedMode + "}";
    }
}
