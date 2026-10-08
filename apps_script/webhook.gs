/**
 * Google Apps Script — Google Form → Webhook bridge
 *
 * This script runs in the Google Apps Script editor (script.google.com).
 * It triggers on every new Google Form submission, reads the linked
 * spreadsheet row, and POSTs the payload to the strategy-call-agent webhook.
 *
 * Phase 6E enhancements:
 * - Request ID tracking (X-Request-ID header) for idempotency
 * - Retry with exponential backoff on transient failures (429, 5xx)
 * - Response validation and detailed diagnostic logging
 * - X-Webhook-Source header to identify Apps Script traffic
 *
 * SETUP (one-time, per Google account):
 * 1. Open your Google Form → Responses → View responses (opens linked Sheet)
 * 2. In the Sheet menu: Extensions → Apps Script
 * 3. Paste this entire file
 * 4. In Apps Script: Project Settings (gear icon) → Script Properties
 *    Add these properties:
 *      WEBHOOK_URL_BASE → Your public HTTPS base URL (e.g. https://your-domain.com/webhooks)
 *      ORG_SLUG         → Your organization slug (e.g. "integrated-it-trainings")
 *      WEBHOOK_SECRET   → The shared secret matching the org's webhook_secret on the server
 *
 *    For backward compatibility with single-tenant setups, you may also set:
 *      WEBHOOK_URL      → Full URL (e.g. https://your-domain.com/webhooks/form-submission)
 *                         ORG_SLUG takes precedence when both WEBHOOK_URL_BASE and ORG_SLUG are set.
 *
 *    Optional:
 *      FORM_IDENTIFIER  → A label identifying this form (e.g. "strategy-call", "enrollment")
 *                         Sent in the payload as "form_identifier" for server-side routing.
 *
 * 5. Save → Run `installTrigger` once to register the onFormSubmit trigger
 *
 * The column headers in the linked Sheet are read dynamically from Row 1.
 * Each header (except "Timestamp") becomes a key in the JSON payload.
 * Required-field validation is handled server-side — this script does NOT
 * assume any specific column names.
 */

// ─── Configuration (from Script Properties) ──────────────────────────────────

/**
 * Get a configuration value from Script Properties.
 * These are set ONCE in the Apps Script editor and never committed to Git.
 *
 * @param {string} key - The property key
 * @param {string} defaultValue - Fallback if not set
 * @returns {string} The property value
 */
function getConfig(key, defaultValue) {
  return PropertiesService.getScriptProperties().getProperty(key) || defaultValue;
}

// ─── Trigger installation ────────────────────────────────────────────────────

/**
 * Run this function ONCE to install the onFormSubmit trigger.
 * After running, you'll see it in Triggers (clock icon in the left sidebar).
 */
function installTrigger() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheets()[0]; // first sheet = form responses

  // Remove any existing onFormSubmit triggers to avoid duplicates
  var triggers = ScriptApp.getProjectTriggers();
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === "onFormSubmit") {
      ScriptApp.deleteTrigger(triggers[i]);
    }
  }

  // Install new trigger
  ScriptApp.newTrigger("onFormSubmit")
    .forSpreadsheet(ss)
    .onFormSubmit()
    .create();

  Logger.log("onFormSubmit trigger installed for spreadsheet: " + ss.getName());
}

// ─── Main handler ────────────────────────────────────────────────────────────

/**
 * Triggered automatically when a new Google Form response is submitted.
 * Reads the header row to map column values to the webhook payload keys.
 *
 * @param {Object} e - The form submit event object (provided by the trigger)
 */
function onFormSubmit(e) {
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheets()[0];

  // Read the header row (row 1) to get column names
  var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];

  // Read the submitted row — the event provides the row index
  var row = e.range.getRow();
  var values = sheet.getRange(row, 1, 1, sheet.getLastColumn()).getValues()[0];

  // Build payload: map each header to its value
  var payload = {};
  for (var i = 0; i < headers.length; i++) {
    var header = headers[i];
    if (header && header !== "Timestamp") {
      // Skip the auto-added Timestamp column from Google Forms
      payload[header] = values[i] !== null ? String(values[i]) : "";
    }
  }

  // NOTE: Required-field validation is handled server-side by Pydantic
  // (FormSubmission schema). We do NOT hardcode specific form-label
  // requirements here — organizations may use different question names.
  // If a required field is missing the webhook will return 422.

  // Optional: attach form_identifier if configured in Script Properties.
  // The server can use this to route to the correct field mapping when
  // an organization has multiple Google Forms with different question labels.
  var formIdentifier = getConfig("FORM_IDENTIFIER", "");
  if (formIdentifier) {
    payload["form_identifier"] = formIdentifier;
  }

  // POST to the webhook (Phase 6E: includes requestId tracking and retry)
  var result = sendToWebhook(payload);
  Logger.log("Webhook result: statusCode=" + result.statusCode + " body=" + result.body);
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────

/**
 * Send the form payload to the backend webhook endpoint.
 *
 * Phase 6E enhancements:
 * - Generates a unique requestId for idempotency tracking on the server
 * - Retries with exponential backoff on transient failures (429, 5xx)
 * - Validates response structure and logs detailed diagnostics
 * - Sends X-Webhook-Source header to identify this as Apps Script traffic
 *
 * When ORG_SLUG is configured, sends to /webhooks/{org_slug}/form-submission.
 * Falls back to the legacy WEBHOOK_URL for backward compatibility.
 *
 * @param {Object} payload - The form data keyed by question label
 * @returns {Object} {statusCode, body}
 */
function sendToWebhook(payload) {
  // Build the webhook URL: prefer org-scoped route when ORG_SLUG is set
  var webhookUrl = "";
  var orgSlug = getConfig("ORG_SLUG", "");
  var baseUrl = getConfig("WEBHOOK_URL_BASE", "");

  if (orgSlug && baseUrl) {
    // Org-scoped route: POST /webhooks/{org_slug}/form-submission
    webhookUrl = baseUrl.replace(/\/$/, "") + "/" + orgSlug + "/form-submission";
  } else {
    // Legacy route: POST /webhooks/form-submission (backward compatible)
    webhookUrl = getConfig("WEBHOOK_URL", "");
  }

  if (!webhookUrl) {
    Logger.log("ERROR: Neither WEBHOOK_URL_BASE+ORG_SLUG nor WEBHOOK_URL set in Script Properties.");
    Logger.log("Go to Project Settings → Script Properties and add the required values.");
    return { statusCode: 0, body: "WEBHOOK_URL not configured" };
  }

  // Phase 6E: Generate unique request ID for idempotency tracking
  var requestId = Utilities.getUuid();

  // Phase 6E: Retry with exponential backoff
  var maxRetries = 3;
  var baseDelayMs = 1000; // 1 second base delay

  for (var attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      // Exponential backoff: 1s, 2s, 4s
      var delayMs = baseDelayMs * Math.pow(2, attempt - 1);
      Logger.log("Retry attempt " + attempt + "/" + maxRetries + " after " + delayMs + "ms delay");
      Utilities.sleep(delayMs);
    }

    var options = {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true, // don't throw on non-2xx responses
      followRedirects: true,
    };

    // Build headers
    var headers = {};

    // Add Bearer token authentication if WEBHOOK_SECRET is set
    var secret = getConfig("WEBHOOK_SECRET", "");
    if (secret) {
      headers["Authorization"] = "Bearer " + secret;
    }

    // Phase 6E: Add request ID for idempotency tracking
    headers["X-Request-ID"] = requestId;

    // Phase 6E: Identify this as Apps Script traffic
    headers["X-Webhook-Source"] = "apps-script";

    options.headers = headers;

    try {
      var response = UrlFetchApp.fetch(webhookUrl, options);
      var statusCode = response.getResponseCode();
      var body = response.getContentText();

      // Phase 6E: Log detailed response diagnostics
      Logger.log("Webhook response: " + statusCode + " — requestId=" + requestId + " — attempt=" + (attempt + 1));

      // Phase 6E: Retry on transient failures (rate limiting, server errors)
      if (statusCode === 429 || statusCode >= 500) {
        Logger.log("Transient failure (HTTP " + statusCode + "), will retry if attempts remain");
        if (attempt < maxRetries) {
          continue; // retry
        }
        // Last attempt failed with transient error
        Logger.log("ERROR: All " + (maxRetries + 1) + " attempts exhausted. Last status: " + statusCode);
        return { statusCode: statusCode, body: body };
      }

      // Phase 6E: Validate response body for accepted/duplicate
      try {
        var parsed = JSON.parse(body);
        Logger.log("Parsed response: status=" + parsed.status + " lead_id=" + (parsed.lead_id || "n/a") + " request_id=" + (parsed.request_id || "n/a"));
      } catch (parseErr) {
        // Response is not JSON — log but don't fail
        Logger.log("WARNING: Response is not JSON: " + body.substring(0, 200));
      }

      // Non-transient response (2xx, 4xx other than 429) — don't retry
      return { statusCode: statusCode, body: body };

    } catch (fetchErr) {
      // Network error (DNS, timeout, connection refused)
      Logger.log("Fetch error on attempt " + (attempt + 1) + ": " + fetchErr.message);
      if (attempt < maxRetries) {
        continue; // retry
      }
      Logger.log("ERROR: All " + (maxRetries + 1) + " attempts exhausted. Last error: " + fetchErr.message);
      return { statusCode: 0, body: fetchErr.message };
    }
  }

  // Should never reach here, but just in case
  return { statusCode: 0, body: "Unexpected error in retry loop" };
}
