/**
 *  Pi-hole Virtual Switch Device Driver (Updated for Pi-hole v6 API)
 *
 *  Originally created by:
 *    - Nick Veenstra (2018)
 *    - Converted to Hubitat by cuboy29
 *    - Community contributions from harriscd
 *    - Updates by Jed Brown
 *
 *  Revision History:
 *    - 2020.08: Hubitat Community Forum Release
 *    - 2023.01.10: Updated to fix polling per API changes in Pi-hole
 *    - 2023.01.12: Added debugging toggle, optional API token, simplified code
 *    - 2023.01.13: Fixed issue for Pi-holes without passwords
 *    - 2025.02.21: Updated for Pi-hole v6 API changes, added HPM support (by WalksOnAir)
 *    - 2025.02.22: Updated with user selectable port (by Alan_F)
 *    - 2025.05.04: Added HTTPS support with certificate validation options
 *    - 2025.05.04: Updated to support FQDN hostnames with DNS resolution
 *    - 2025.05.04: Updated for Pi-hole v6 REST API compatibility
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

metadata {
    definition (name: "PiHole Virtual Switch", namespace: "WalksOnAir", author: "WalksOnAir") {
        capability "Switch"

        command "poll"

        attribute "lastupdate", "string"
        attribute "sessionValid", "string"
        attribute "blockingWillResumeAt", "string"
        attribute "hardwareStatus", "string" 
        attribute "serviceStatus", "string"  
    }
   
    preferences {
        section ("Settings") {
            input name: "deviceIP", type: "text", title: "Pi-hole IP address or hostname", required: true
            input name: "devicePort", type: "text", title: "Pi-hole Port (required)", required: true, defaultValue: "80"
            input name: "useHttps", type: "bool", title: "Use HTTPS Connection", required: false, defaultValue: false
            input name: "ignoreSSLIssues", type: "bool", title: "Ignore SSL Certificate Issues", required: false, defaultValue: false
            input name: "piPassword", type: "password", title: "Pi-hole Password (required):", required: true
            input name: "disableTime", type: "number", title: "Disable time in minutes (1..1440; Blank = indefinitely):", required: false, range: "1..1440"
            input name: "pollingInterval", type: "number", title: "Polling Interval (minutes):", required: false, defaultValue: 10, range: "1..60"
            input name: "isDebug", type: "bool", title: "Enable Debug Logging", required: false, defaultValue: false
            input name: "redactSensitiveInfo", type: "bool", title: "Redact Sensitive Info in Logs", required: false, defaultValue: true
        }
    }
}

def installed() {
    logDebug("Installed with settings: ${redactSettings(settings)}")
    initialize()
}

def updated() {
    logDebug("Updated with settings: ${redactSettings(settings)}")

    def previousDebug = state.previousDebug
    state.previousDebug = isDebug

    if (previousDebug != null && previousDebug != isDebug) {
        log.info "Debug logging is ${isDebug ? 'ENABLED' : 'DISABLED'}."
    }

    initialize()
}

def initialize() {
    if (isDebug == null) isDebug = false

    logDebug("Initializing Pi-hole Virtual Switch...")
    
    // If we're using a hostname/FQDN and it's time to refresh DNS, do an initial ping
    // This will resolve and cache the IP address
    if (deviceIP =~ /[a-zA-Z]/ && shouldRefreshDns()) {
        logDebug("Hostname detected and DNS cache expired. Performing initial DNS resolution...")
        pingPiHole()
    }
    
    if (state.sid && device.currentValue("sessionValid") == "true") {
        logDebug("Valid session found. Skipping authentication.")
    } else {
        logDebug("No valid session found. Re-authenticating...")
        state.sid = null
        state.csrf = null
        sendEvent(name: "sessionValid", value: "unknown")
        authenticate()
    }

    def interval = settings.pollingInterval ? settings.pollingInterval.toInteger() : 10
    log.info "Setting polling interval to ${interval} minutes."
    schedule("0 0/${interval} * * * ?", "poll")
}

def refresh() {
    poll()
}

def poll() {
    logDebug("POLL button pressed: Checking Pi-hole hardware and service status...")

    if (!pingPiHole()) {
        log.warn "Pi-hole hardware is unreachable! Network issue or device is off."
        sendEvent(name: "deviceStatus", value: "Offline (No Ping)")
        sendEvent(name: "serviceStatus", value: "Unknown (Device Offline)")
        return
    }

    sendEvent(name: "deviceStatus", value: "Online (Hardware OK)")

    ensureSessionValid()

    if (!testApiAvailability()) {
        log.warn "Pi-hole API is unreachable or authentication failed. Re-authenticating..."
        authenticate()
        return
    }

    sendRequest("GET", "/dns/blocking", null, "handleStatusResponse")
}

def ensureSessionValid() {
    if (!state.sid || device.currentValue("sessionValid") == "false") {
        log.warn "No valid session ID or session expired. Re-authenticating..."
        authenticate()
    }
}

def on() {
    logDebug("ON button pressed: Enabling blocking")

    if (device.currentValue("serviceStatus") == "Down (Service Unavailable)") {
        log.warn "Cannot enable blocking - Pi-hole service is currently down!"
        return
    }

    ensureSessionValid()
    def payload = [ "blocking": true ]
    
    sendRequest("POST", "/dns/blocking", payload, "handleOnResponse")
}

def handleOnResponse(hubitat.device.HubResponse response) {
    if (response.status == 200) {
        log.info "Successfully enabled Pi-hole blocking."

        sendEvent(name: "blockingWillResumeAt", value: "N/A")
        state.disableEndTime = null
        
        sendEvent(name: "switch", value: "on")

        runIn(2, poll) 
    } else {
        log.warn "Failed to enable Pi-hole blocking. API Response: ${response.status}"
    }
}

def off() {
    logDebug("OFF button pressed: Disabling blocking for ${disableTime} minutes")

    if (device.currentValue("serviceStatus") == "Down (Service Unavailable)") {
        log.warn "Cannot disable blocking - Pi-hole service is currently down!"
        return
    }

    ensureSessionValid()
    def disableTimeInSeconds = (disableTime && disableTime > 0) ? disableTime * 60 : 0
    def payload = [ "blocking": false ]
    
    // Add timer parameter only if disableTime is defined and greater than 0
    if (disableTimeInSeconds > 0) {
        payload.timer = disableTimeInSeconds
    }

    sendRequest("POST", "/dns/blocking", payload, "handleOffResponse")
}

def handleOffResponse(hubitat.device.HubResponse response) {
    if (response.status == 200) {
        log.info "Successfully disabled Pi-hole blocking. API Response: ${response.status}"

        def disableTimeInSeconds = (disableTime && disableTime > 0) ? disableTime * 60 : 0

        if (disableTimeInSeconds > 0) {
            def resumeTime = new Date(now() + (disableTimeInSeconds * 1000))
            def formattedResumeTime = resumeTime.format("yyyy-MM-dd HH:mm:ss", location.timeZone)

            log.info "Pi-hole blocking will resume at: ${formattedResumeTime}"
            sendEvent(name: "blockingWillResumeAt", value: formattedResumeTime)
            state.disableEndTime = now() + (disableTimeInSeconds * 1000)

            runEvery1Minute("updateBlockingResumeTime")
        } else {
            log.warn "Pi-hole blocking is disabled indefinitely based on preferences."
            sendEvent(name: "blockingWillResumeAt", value: "Indefinitely Disabled")
            state.disableEndTime = null
        }
        
        sendEvent(name: "switch", value: "off")

        runIn(2, poll) 
    } else {
        log.error "Failed to disable Pi-hole blocking. API Response: ${response.status}"
        sendEvent(name: "blockingWillResumeAt", value: "N/A")
    }
}

def updateBlockingResumeTime() {
    if (!state.disableEndTime) {
        sendEvent(name: "blockingWillResumeAt", value: "N/A")
        return
    }

    def timeLeftMillis = state.disableEndTime - now()
    
    if (timeLeftMillis <= 0) {
        sendEvent(name: "blockingWillResumeAt", value: "N/A")
        log.info "Checking if Pi-hole re-enabled blocking..."
        poll()
        state.disableEndTime = null
        return
    }

    def resumeTime = new Date(state.disableEndTime)
    sendEvent(name: "blockingWillResumeAt", value: resumeTime.format("yyyy-MM-dd HH:mm:ss", location.timeZone))
}

def authenticate() {
    if (!settings.piPassword) {
        log.error "Pi-hole password is not set. Cannot authenticate."
        return
    }

    log.info "Attempting Pi-hole v6 API authentication..."
    state.sid = null
    state.csrf = null
    sendEvent(name: "sessionValid", value: "authenticating")

    def payload = new groovy.json.JsonBuilder([ "password": settings.piPassword.trim() ]).toString()

    try {
        def protocol = getProtocol()
        
        def params = [
            uri: "${protocol}://${deviceIP}:${devicePort}/api/auth",
            headers: ["Content-Type": "application/json"],
            body: payload,
            timeout: 5
        ]
        
        // Add ignoreSSL option if using HTTPS and ignoreSSLIssues is enabled
        if (useHttps && ignoreSSLIssues) {
            params.ignoreSSLIssues = true
        }
        
        httpPost(params) { response ->
            if (response.status == 200) {
                def jsonResponse = response.data
                
                if (jsonResponse?.session?.valid == true && jsonResponse.session?.sid) {
                    state.sid = jsonResponse.session.sid  
                    state.csrf = jsonResponse.session.csrf
                    sendEvent(name: "sessionValid", value: "true") 
                    sendEvent(name: "serviceStatus", value: "Online (Running)")
                    log.info "Authenticated successfully with Pi-hole v6 API."
                    logDebug("Session ID: ${state.sid}, CSRF Token: ${state.csrf}, Validity: ${jsonResponse.session.validity} seconds")

                    runIn(2, poll)
                } else {
                    log.warn "Authentication failed: No valid session ID returned."
                    state.sid = null
                    state.csrf = null
                    sendEvent(name: "sessionValid", value: "false")
                    runIn(10, authenticate) 
                }
            } else {
                log.error "Authentication failed with status ${response.status}: ${response.data}"
                state.sid = null
                state.csrf = null
                sendEvent(name: "sessionValid", value: "false")

                def retryDelay = state.authRetryDelay ?: 5
                runIn(retryDelay, authenticate)
                state.authRetryDelay = Math.min(retryDelay * 2, 60)
            }
        }
    } catch (Exception e) {
        log.error "Error during authentication: ${e.message}"
        state.sid = null
        state.csrf = null
        sendEvent(name: "sessionValid", value: "false")
    }
}

def handleAuthResponse(hubitat.device.HubResponse response) {
    if (response.status == 200) {
        def json = response.getJson()
        if (json?.session?.valid == true && json.session?.sid) {
            state.sid = json.session.sid  
            state.csrf = json.session.csrf
            sendEvent(name: "sessionValid", value: "true") 
            sendEvent(name: "serviceStatus", value: "Online (Running)")
            log.info "Authenticated successfully. New Session ID and CSRF Token obtained."

            runIn(2, poll)
        } else {
            log.warn "Authentication failed: Response did not contain a valid session ID."
            state.sid = null
            state.csrf = null
            sendEvent(name: "sessionValid", value: "false")
            runIn(10, authenticate)
        }
    } else {
        log.error "Authentication failed with status ${response.status}: ${response.body}"
        state.sid = null
        state.csrf = null
        sendEvent(name: "sessionValid", value: "false")

        def retryDelay = state.authRetryDelay ?: 5
        runIn(retryDelay, authenticate)
        state.authRetryDelay = Math.min(retryDelay * 2, 60)
    }
}

def handleOnOffResponse(hubitat.device.HubResponse response) {
    if (response.status == 200) {
        poll()
        if (state.disableEndTime) {
            runEvery1Minute("updateBlockingResumeTime")
        }
    }
}

def handleStatusResponse(hubitat.device.HubResponse response) {
    if (response.status == 200) {
        def json = response.getJson()

        if (json?.blocking != null) {
            // Pi-hole v6 returns a boolean value for blocking instead of a string
            def blockingEnabled = json.blocking
            def switchState = blockingEnabled ? "on" : "off"
            sendEvent(name: "switch", value: switchState)

            if (device.currentValue("serviceStatus") == "Down (Service Unavailable)") {
                log.warn "Pi-hole service is BACK ONLINE. Re-authenticating..."
                authenticate()
            }
            sendEvent(name: "serviceStatus", value: "Online (Running)")

            log.info "Pi-hole blocking is currently: ${switchState.toUpperCase()}"
        } else {
            log.warn "Unexpected response format from Pi-hole API."
        }
    } else if (response.status == 401) {
        log.warn "Pi-hole API returned 401 Unauthorized. Re-authenticating and retrying request..."
        authenticate()
        runIn(5, poll)
    } else if (response.status in [500, 502, 503, 504]) {
        log.error "Pi-hole API is DOWN! (Error ${response.status})"
        sendEvent(name: "serviceStatus", value: "Service Down (${response.status})")
    } else {
        log.warn "Pi-hole API request failed with HTTP ${response.status}"
        sendEvent(name: "serviceStatus", value: "Unknown API Error")
    }
}

def handleApiHealthResponse(hubitat.device.HubResponse response) {
    if (response.status == 200) {
        logDebug("Pi-hole API is online and accessible.")
        sendEvent(name: "deviceStatus", value: "Online")

        sendRequest("GET", "/api/dns/blocking", null, "handleStatusResponse")
    } else if (response.status == 301) {
        log.warn "Pi-hole API is returning HTTP 301 (Moved Permanently). Check if the API is redirecting to HTTPS."
        sendEvent(name: "deviceStatus", value: "Redirected (301)")
    } else {
        log.warn "Pi-hole API is not responding as expected! HTTP ${response.status}"
        sendEvent(name: "deviceStatus", value: "Service Down")
    }
}

def sendRequest(String method, String endpoint, Map payload, String callbackMethod, boolean isAuth = false) {
    if (!deviceIP) {
        log.warn "No Pi-hole IP set in preferences!"
        return
    }

    def protocol = getProtocol()
    def headers = [
        "Content-Type": "application/json",
        "HOST": "${deviceIP}:${devicePort}"
    ]

    // In Pi-hole v6, authentication headers are different
    if (!isAuth && state.sid) {
        headers["X-FTL-SID"] = state.sid
    }
    if (!isAuth && state.csrf) {
        headers["X-FTL-CSRF"] = state.csrf
    }

    // For GET requests, the session ID can be added to the query params
    if (!isAuth && state.sid && method == "GET") {
        endpoint = "${endpoint}?sid=${URLEncoder.encode(state.sid, 'UTF-8')}"
    }

    // For POST requests, the session ID is included in the payload
    if (!isAuth && state.sid && method == "POST") {
        if (payload == null) {
            payload = [:]
        }
        payload.sid = state.sid
    }

    def safePayload = payload ? new groovy.json.JsonBuilder(payload).toString() : null

    logDebug("Sending request - Protocol: ${protocol}, Method: ${method}, Path: ${endpoint}")
    logDebug("Headers: ${headers}")
    logDebug("Payload: ${safePayload ?: 'No Payload'}")  

    try {
        def hubAction = new hubitat.device.HubAction([
            method: method,
            path: "/api${endpoint}",
            headers: headers,
            body: safePayload
        ], 
        "${protocol}:${deviceIP}:${devicePort}", 
        [callback: callbackMethod])

        sendHubCommand(hubAction)
        logDebug("Request sent to Pi-hole API. Awaiting response...")
    } catch (Exception e) {
        log.error "Unexpected error while sending request: ${e.message}"
        sendEvent(name: "serviceStatus", value: "Unknown Error")
    }
}

private boolean testApiAvailability() {
    def protocol = getProtocol()
    def url = "${protocol}://${deviceIP}:${devicePort}/api/dns/blocking"
    def headers = ["Content-Type": "application/json"]

    if (state.sid) {
        headers["X-FTL-SID"] = state.sid
    }
    if (state.csrf) {
        headers["X-FTL-CSRF"] = state.csrf
    }

    try {
        def params = [
            uri: url, 
            headers: headers, 
            timeout: 5
        ]
        
        // Add ignoreSSL option if using HTTPS and ignoreSSLIssues is enabled
        if (useHttps && ignoreSSLIssues) {
            params.ignoreSSLIssues = true
        }
        
        httpGet(params) { response ->
            if (response.status == 200) {
                logDebug("Pi-hole API is online (HTTP 200).")
                sendEvent(name: "serviceStatus", value: "Online (Running)")
                return true
            } else if (response.status == 401) {
                log.warn "Pi-hole API returned 401 Unauthorized. Re-authenticating..."
                
                state.sid = null
                state.csrf = null
                sendEvent(name: "sessionValid", value: "false")

                authenticate()
                runIn(5, poll)
                return false
            } else {
                log.warn "Unexpected Pi-hole API response: HTTP ${response.status}"
                sendEvent(name: "serviceStatus", value: "Unknown API Error")
                return false
            }
        }
    } catch (Exception e) {
        log.warn "Pi-hole API is unreachable: ${e.message}"

        if (e.message.contains("Connection refused")) {
            log.warn "Pi-hole service is DOWN (Connection Refused)."
            sendEvent(name: "serviceStatus", value: "Down (Service Unavailable)")
            sendEvent(name: "sessionValid", value: "false")
            state.sid = null
            state.csrf = null
        } else if (e.message.contains("SSL") || e.message.contains("certificate")) {
            log.warn "Pi-hole SSL certificate issue detected. Consider enabling 'Ignore SSL Certificate Issues' in preferences."
            sendEvent(name: "serviceStatus", value: "SSL Error")
            sendEvent(name: "sessionValid", value: "false")
            state.sid = null
            state.csrf = null
        } else {
            sendEvent(name: "serviceStatus", value: "Unknown Network Error")
        }

        return false
    }
}

def logDebug(msg) {
    if (isDebug == true) {
        log.debug "${msg}"
    }
}

// Helper method to get the protocol (http/https) based on preferences
private String getProtocol() {
    return useHttps ? "https" : "http"
}

// Check if we need to re-resolve the DNS (every 6 hours by default)
private boolean shouldRefreshDns() {
    if (!state.lastDnsResolution) return true
    
    // Default DNS cache expiration is 6 hours (in milliseconds)
    def dnsCacheExpirationMs = 6 * 60 * 60 * 1000
    
    return (now() - state.lastDnsResolution) > dnsCacheExpirationMs
}

private redactSettings(settingsMap) {
    if (!settingsMap) return [:]

    def safeSettings = settingsMap.clone()

    if (redactSensitiveInfo) {
        if (safeSettings.piPassword) safeSettings.piPassword = "[REDACTED]"
        if (safeSettings.apiToken) safeSettings.apiToken = "[REDACTED]"
    }

    return safeSettings
}

def pingPiHole() {
    def targetAddress = deviceIP
    
    // Check if the deviceIP is an FQDN (contains alphabetic characters)
    if (deviceIP =~ /[a-zA-Z]/) {
        logDebug("Pi-hole address '${deviceIP}' appears to be an FQDN.")
        
        // Try to use stored IP if we have one
        if (state.resolvedIP && !shouldRefreshDns()) {
            logDebug("Using cached IP address: ${state.resolvedIP}")
            targetAddress = state.resolvedIP
        } else {
            // Alternative approach - try to check if Pi-hole is available via HTTP
            logDebug("Checking Pi-hole availability via HTTP request...")
            
            try {
                def protocol = getProtocol()
                def uri = "${protocol}://${deviceIP}:${devicePort}/admin/"
                logDebug("Testing connection to: ${uri}")
                
                httpHead(uri: uri, timeout: 5) { response ->
                    if (response.status == 200 || response.status == 301 || response.status == 302) {
                        log.info "Pi-hole admin interface is accessible at ${uri}"
                        // Since we can reach the admin interface, we'll consider the device online
                        return true
                    }
                }
            } catch (Exception e) {
                logDebug("HTTP connection test failed: ${e.message}")
            }
        }
    } else {
        logDebug("Pi-hole address '${deviceIP}' appears to be an IP address.")
    }
    
    logDebug("Testing connection to Pi-hole server at ${targetAddress}...")

    // Try a direct API call instead of relying on ping
    try {
        def protocol = getProtocol()
        def uri = "${protocol}://${targetAddress}:${devicePort}/api/dns/info"
        logDebug("Testing Pi-hole API connection to: ${uri}")
        
        def params = [
            uri: uri,
            timeout: 5
        ]
        
        // Add ignoreSSL option if using HTTPS and ignoreSSLIssues is enabled
        if (useHttps && ignoreSSLIssues) {
            params.ignoreSSLIssues = true
        }
        
        def apiAccessible = false
        
        httpGet(params) { response ->
            if (response.status >= 200 && response.status < 300) {
                log.info "Pi-hole API is accessible at ${uri}"
                apiAccessible = true
            } else {
                logDebug("Pi-hole API returned status code: ${response.status}")
            }
        }
        
        if (apiAccessible) {
            return true
        }
    } catch (Exception e) {
        logDebug("Pi-hole API connection test failed: ${e.message}")
    }
    
    // As a last resort, try the NetworkUtils.ping method, but handle null result
    try {
        logDebug("Attempting to ping ${targetAddress} using NetworkUtils...")
        
        // First check if NetworkUtils is available in this Hubitat version
        if (hubitat.helper.NetworkUtils.respondsTo('ping')) {
            def pingResult = hubitat.helper.NetworkUtils.ping(targetAddress, 1)
            
            if (pingResult == null) {
                logDebug("Ping operation returned null result")
                // Don't return false yet, let the HTTP check below have a chance
            } else {
                logDebug("Ping completed. Raw results: ${pingResult}")
                
                // Try to determine success based on string representation
                if (pingResult.toString().contains("packetsReceived=1") || 
                   pingResult.toString().contains("packetsReceived: 1")) {
                    log.info "Pi-hole server at ${targetAddress} responded to ping"
                    return true
                }
            }
        } else {
            logDebug("NetworkUtils.ping method is not available in this Hubitat version")
        }
    } catch (Exception e) {
        logDebug("Error while attempting ping: ${e.message}")
    }
    
    // If all methods fail, try a simple HTTP request as last resort
    try {
        def protocol = getProtocol()
        def uri = "${protocol}://${targetAddress}:${devicePort}"
        logDebug("Final attempt - testing basic HTTP connection to: ${uri}")
        
        def params = [
            uri: uri,
            timeout: 3
        ]
        
        if (useHttps && ignoreSSLIssues) {
            params.ignoreSSLIssues = true
        }
        
        httpHead(params) { response ->
            if (response.status) {
                log.info "Pi-hole server at ${targetAddress} responded to HTTP request with status: ${response.status}"
                return true
            }
        }
    } catch (Exception e) {
        log.warn "Pi-hole server at ${targetAddress} is unreachable: ${e.message}"
    }
    
    log.warn "Pi-hole server at ${targetAddress} appears to be OFFLINE after multiple connection attempts"
    return false
}