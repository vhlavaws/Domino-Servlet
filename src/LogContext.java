public class LogContext {

   public final long startTime;

   // NOT final fields to allow updates across methods

   // Caller info
   public String ipAddress, userAgent, httpMethod, requestUri;

   // Request params
   public String action, target;
 
   // Target properties
   public String targetName, targetApiUrl, mode, targetApiVersion, targetMethod;

   // Response properties
   public String errorMsg, apiData;
   public int httpCode;
   public long durationMs = 0;
  
   String result = ""; // "success", "error", "cached", etc. - for easier querying/logging
   String success = "0";

   // Async/cached mode properties
   public boolean isAsync, isCachedResponseUsed;
   public long cacheResponseTime;

   public LogContext() {
      this.startTime = System.currentTimeMillis();
   }

   public LogContext(long startTime) {
      this.startTime = startTime;
   }

  // Fluid setters to mimic Builder behavior
   public LogContext setCaller(String ip, String userAgent, String httpMethod, String requestUri) {
      this.ipAddress = ip;
      this.userAgent = userAgent;
      this.httpMethod = httpMethod;
      this.requestUri = requestUri;
      return this;
   }

   public LogContext setCaller(String ip, String userAgent, String httpMethod) {
      this.ipAddress = ip;
      this.userAgent = userAgent;
      this.httpMethod = httpMethod;
      return this;
   }

   public LogContext setRequesContext(String action, String target) {
       this.targetName = target;
       this.action = action;
       return this;
   }
    
   public LogContext setTarget(String apiName, String apiUrl, String httpMethod, String apiVersion, String mode) {
       this.targetName = apiName;
       this.targetApiUrl = apiUrl;
       this.targetMethod = httpMethod;
       this.targetApiVersion = apiVersion;
       this.mode = mode;
      
       return this;
   }

   public LogContext setHttpCode(int val) {
      this.httpCode = val;
      return this;
   }

   public LogContext setErrorMsg(String val) {
      this.errorMsg = val;
      return this;
   }

   public LogContext setAsync(boolean val) {
      this.isAsync = val;
      return this;
   }

   public LogContext setCachedResponseUsed(boolean val) {
      this.isCachedResponseUsed = val;
      return this;
   }

   public LogContext setCacheReplyTime(long val) {
      this.cacheResponseTime = val;
      return this;
   }

   public LogContext setDurationMs(long val) {
      this.durationMs = val;
      return this;
   }

   public LogContext setResults(int httpCode, String errMsg, String apiData) {
      this.httpCode = httpCode;
      this.errorMsg = errMsg;
      this.apiData = apiData; 
      if (errMsg != null && errMsg.length() > 0) {
         this.result = "error";
         this.success = "0";
      } else {
         this.result = "success";
         this.success = "1";  
      }
      return this;
   }

   public LogContext setResult(boolean isSuccess, String result) {
         this.success = isSuccess ? "1" : "0";
         this.result = result;
         return this;
   }

   public long getDurationMs() {
      return durationMs > 0 ? durationMs : System.currentTimeMillis() - this.startTime;
   }

}
