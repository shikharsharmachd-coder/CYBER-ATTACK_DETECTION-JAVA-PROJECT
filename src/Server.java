
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Server {

    private static final Map<String, Long> activeSessions =
            new ConcurrentHashMap<>();

    private static final long SESSION_DURATION =
            8 * 60 * 60 * 1000L;

    private static final SecureRandom secureRandom =
            new SecureRandom();

    public static void main(String[] args) throws IOException {

        HttpServer server = HttpServer.create(
                new InetSocketAddress(8080), 0
        );

        // API 1: Check server status (public)
        server.createContext("/api/status", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            sendResponse(exchange, 200,
                    "{\"status\":\"running\",\"message\":\"CyberGuard backend is working!\"}");
        });

        // API 2: Administrator login
        server.createContext("/api/login", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            String adminUsername = System.getenv("ADMIN_USERNAME");
            String adminPassword = System.getenv("ADMIN_PASSWORD");

            if (adminUsername == null || adminPassword == null
                    || adminUsername.isBlank() || adminPassword.isBlank()) {

                sendResponse(exchange, 503,
                        "{\"error\":\"Admin credentials are not configured on the server\"}");
                return;
            }

            try {

                String requestBody = new String(
                        exchange.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> data = parseFormData(requestBody);

                String username = data.getOrDefault("username", "");
                String password = data.getOrDefault("password", "");

                boolean usernameMatches =
                        MessageDigest.isEqual(
                                username.getBytes(StandardCharsets.UTF_8),
                                adminUsername.getBytes(StandardCharsets.UTF_8)
                        );

                boolean passwordMatches =
                        MessageDigest.isEqual(
                                password.getBytes(StandardCharsets.UTF_8),
                                adminPassword.getBytes(StandardCharsets.UTF_8)
                        );

                if (!usernameMatches || !passwordMatches) {

                    sendResponse(exchange, 401,
                            "{\"error\":\"Invalid username or password\"}");
                    return;
                }

                byte[] tokenBytes = new byte[32];
                secureRandom.nextBytes(tokenBytes);

                String token = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(tokenBytes);

                activeSessions.put(
                        token,
                        System.currentTimeMillis() + SESSION_DURATION
                );

                sendResponse(exchange, 200,
                        "{"
                                + "\"status\":\"success\","
                                + "\"message\":\"Login successful\","
                                + "\"token\":" + jsonQuote(token)
                                + "}"
                );

            } catch (Exception e) {

                e.printStackTrace();

                sendResponse(exchange, 400,
                        "{\"error\":\"Invalid login request\"}");
            }
        });

        // API 3: Verify administrator session
        server.createContext("/api/session", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            if (!isAuthenticated(exchange)) {
                sendResponse(exchange, 401,
                        "{\"authenticated\":false,\"error\":\"Authentication required\"}");
                return;
            }

            sendResponse(exchange, 200,
                    "{\"authenticated\":true}");
        });

        // API 4: Administrator logout
        server.createContext("/api/logout", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            String token = getToken(exchange);

            if (token != null) {
                activeSessions.remove(token);
            }

            sendResponse(exchange, 200,
                    "{\"status\":\"success\",\"message\":\"Logged out successfully\"}");
        });

        // Paginated log browser endpoint with an optional time range.
        server.createContext("/api/logs/page", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;
            if (!requireAuthentication(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            Map<String, String> query = parseFormData(
                    exchange.getRequestURI().getRawQuery() == null
                            ? ""
                            : exchange.getRequestURI().getRawQuery()
            );

            try {
                String range = query.getOrDefault("days", "all");
                int days = range.equalsIgnoreCase("all") ? 0 : Integer.parseInt(range);
                int page = Integer.parseInt(query.getOrDefault("page", "1"));
                int pageSize = Integer.parseInt(query.getOrDefault("pageSize", "10"));

                if ((days != 0 && days != 3 && days != 7 && days != 15
                        && days != 30 && days != 90)
                        || page < 1 || page > 1_000_000
                        || (pageSize != 10 && pageSize != 25 && pageSize != 50)) {
                    sendResponse(exchange, 400,
                            "{\"error\":\"Invalid log query\"}");
                    return;
                }

                sendResponse(exchange, 200,
                        LogDAO.getLogsPage(days, page, pageSize));

            } catch (NumberFormatException e) {
                sendResponse(exchange, 400,
                        "{\"error\":\"Invalid log query\"}");
            } catch (SQLException e) {
                e.printStackTrace();
                sendResponse(exchange, 500,
                        "{\"error\":\"Unable to retrieve security logs\"}");
            }
        });

        // API 5: Submit and retrieve security logs (protected)
        server.createContext("/api/logs", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!requireAuthentication(exchange)) return;

            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {

                try {

                    String logs = LogDAO.getRecentLogs();
                    sendResponse(exchange, 200, logs);

                } catch (SQLException e) {

                    e.printStackTrace();

                    sendResponse(exchange, 500,
                            "{\"error\":\"Unable to retrieve security logs\"}");
                }

                return;
            }

            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            try {

                String requestBody = new String(
                        exchange.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

                Map<String, String> data = parseFormData(requestBody);

                String ip = data.getOrDefault("ipAddress", "").trim();
                String type = data.getOrDefault("eventType", "").trim();
                String description = data.getOrDefault("description", "").trim();
                String severity = data.getOrDefault("severity", "").trim();

                if (ip.isBlank() || type.isBlank()
                        || description.isBlank() || severity.isBlank()) {

                    sendResponse(exchange, 400,
                            "{\"error\":\"All fields are required\"}");
                    return;
                }

                LogEntry log = new LogEntry(
                        ip, type, description, severity
                );

                String detectionResult = DetectionEngine.analyze(log);

                LogDAO.saveLog(log, detectionResult);

                if (detectionResult.startsWith("SUSPICIOUS")) {

                    Alert alert = new Alert(
                            ip,
                            "Security Threat",
                            detectionResult
                    );

                    alert.displayAlert();
                    LogDAO.saveAlert(alert);
                }

                System.out.println("\n===== NEW SECURITY LOG =====");
                log.displayLog();
                System.out.println("Detection Result: " + detectionResult);
                System.out.println("============================");

                String response = "{"
                        + "\"status\":\"success\","
                        + "\"message\":\"Security log processed\","
                        + "\"detection\":" + jsonQuote(detectionResult)
                        + "}";

                sendResponse(exchange, 200, response);

            } catch (Exception e) {

                e.printStackTrace();

                sendResponse(exchange, 400,
                        "{\"error\":\"Invalid request data\"}");
            }
        });

        // API 6: Retrieve dashboard statistics (protected)
        server.createContext("/api/summary", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!requireAuthentication(exchange)) return;

            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                sendResponse(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            try {

                String summary = LogDAO.getDashboardStats();

                sendResponse(exchange, 200, summary);

            } catch (SQLException e) {

                e.printStackTrace();

                sendResponse(exchange, 500,
                        "{\"error\":\"Unable to retrieve dashboard statistics\"}");
            }
        });

        // API 7: Retrieve alerts and resolve incidents (protected)
        server.createContext("/api/alerts", exchange -> {

            addCorsHeaders(exchange);

            if (handleOptions(exchange)) return;

            if (!requireAuthentication(exchange)) return;

            String requestMethod = exchange.getRequestMethod();
            String requestPath = exchange.getRequestURI().getPath();

            // GET /api/alerts
            if (requestMethod.equalsIgnoreCase("GET")) {

                if (!requestPath.equals("/api/alerts")) {
                    sendResponse(exchange, 404,
                            "{\"error\":\"API endpoint not found\"}");
                    return;
                }

                try {

                    String alerts = LogDAO.getRecentAlerts();
                    sendResponse(exchange, 200, alerts);

                } catch (SQLException e) {

                    e.printStackTrace();

                    sendResponse(exchange, 500,
                            "{\"error\":\"Unable to retrieve security alerts\"}");
                }

                return;
            }

            // POST /api/alerts/{alertId}/resolve
            if (requestMethod.equalsIgnoreCase("POST")) {

                String prefix = "/api/alerts/";
                String suffix = "/resolve";

                if (!requestPath.startsWith(prefix)
                        || !requestPath.endsWith(suffix)) {

                    sendResponse(exchange, 404,
                            "{\"error\":\"API endpoint not found\"}");
                    return;
                }

                String encodedAlertId = requestPath.substring(
                        prefix.length(),
                        requestPath.length() - suffix.length()
                );

                if (encodedAlertId.isBlank()
                        || encodedAlertId.contains("/")) {

                    sendResponse(exchange, 400,
                            "{\"error\":\"Invalid alert ID\"}");
                    return;
                }

                try {

                    String alertId = URLDecoder.decode(
                            encodedAlertId,
                            StandardCharsets.UTF_8
                    );

                    boolean resolved = LogDAO.resolveAlert(alertId);

                    if (!resolved) {

                        sendResponse(exchange, 404,
                                "{\"error\":\"Alert not found\"}");
                        return;
                    }

                    sendResponse(exchange, 200,
                            "{"
                                    + "\"status\":\"success\","
                                    + "\"message\":\"Incident resolved successfully\""
                                    + "}"
                    );

                } catch (SQLException e) {

                    e.printStackTrace();

                    sendResponse(exchange, 500,
                            "{\"error\":\"Unable to resolve incident\"}");
                }

                return;
            }

            sendResponse(exchange, 405,
                    "{\"error\":\"Method not allowed\"}");
        });

        server.start();

        System.out.println("==================================");
        System.out.println(" CyberGuard Backend Started!");
        System.out.println(" http://localhost:8080");
        System.out.println(" Authentication: Enabled");
        System.out.println("==================================");
    }

    // Parse URL-encoded form data
    private static Map<String, String> parseFormData(String requestBody) {

        Map<String, String> data = new HashMap<>();

        for (String pair : requestBody.split("&")) {

            String[] parts = pair.split("=", 2);

            if (parts.length == 2) {

                String key = URLDecoder.decode(
                        parts[0], StandardCharsets.UTF_8
                );

                String value = URLDecoder.decode(
                        parts[1], StandardCharsets.UTF_8
                );

                data.put(key, value);
            }
        }

        return data;
    }

    // Get bearer token from request
    private static String getToken(HttpExchange exchange) {

        String authorization = exchange.getRequestHeaders()
                .getFirst("Authorization");

        if (authorization == null
                || !authorization.startsWith("Bearer ")) {
            return null;
        }

        return authorization.substring(7).trim();
    }

    // Verify session token
    private static boolean isAuthenticated(HttpExchange exchange) {

        String token = getToken(exchange);

        if (token == null || token.isBlank()) {
            return false;
        }

        Long expiry = activeSessions.get(token);

        if (expiry == null) {
            return false;
        }

        if (System.currentTimeMillis() > expiry) {
            activeSessions.remove(token);
            return false;
        }

        return true;
    }

    // Reject requests without a valid session
    private static boolean requireAuthentication(HttpExchange exchange)
            throws IOException {

        if (!isAuthenticated(exchange)) {

            sendResponse(exchange, 401,
                    "{\"error\":\"Unauthorized. Please login first.\"}");

            return false;
        }

        return true;
    }

    // Allow frontend development server to communicate with Java
    private static void addCorsHeaders(HttpExchange exchange) {

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Origin", "*"
        );

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Methods", "GET, POST, OPTIONS"
        );

        exchange.getResponseHeaders().set(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization"
        );
    }

    // Handle browser preflight requests
    private static boolean handleOptions(HttpExchange exchange)
            throws IOException {

        if (exchange.getRequestMethod().equalsIgnoreCase("OPTIONS")) {

            exchange.sendResponseHeaders(204, -1);
            exchange.close();

            return true;
        }

        return false;
    }

    // Safely format a Java string as JSON
    private static String jsonQuote(String value) {

        if (value == null) {
            return "null";
        }

        StringBuilder result = new StringBuilder("\"");

        for (char c : value.toCharArray()) {

            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");

                default -> {
                    if (c < 32) {
                        result.append(String.format("\\u%04x", (int) c));
                    } else {
                        result.append(c);
                    }
                }
            }
        }

        return result.append("\"").toString();
    }

    // Common method for sending HTTP responses
    private static void sendResponse(
            HttpExchange exchange,
            int statusCode,
            String response
    ) throws IOException {

        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set(
                "Content-Type", "application/json; charset=UTF-8"
        );

        exchange.sendResponseHeaders(statusCode, responseBytes.length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
