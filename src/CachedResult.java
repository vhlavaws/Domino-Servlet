/**
 * Cached API response for a single target.
 * Used by cached/async mode (e.g. TeamViewer).
 */
public class CachedResult {

    /** HTTP response code from the API (0 if connection failed) */
    public int httpCode;

    /** Raw response body (JSON string) */
    public String data;

    /** Error message if the call failed, null if successful */
    public String errorMsg;

    /** How long the API call took in milliseconds */
    public long durationMs;

    /** System.currentTimeMillis() when this result was captured */
    public long timestamp;
}
