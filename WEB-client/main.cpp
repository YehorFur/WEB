#include "crow.h"
#include <sqlite3.h>
#include <unordered_map>
#include <sstream>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <cstdlib>
#include <ctime>

// Store active sessions
std::map<std::string, std::string> activeSessions;

// Function to generate a session token
std::string generateSessionToken() {
    return std::to_string(std::rand());
}

// Function to initialize the database
void init_db() {
    sqlite3* db;
    sqlite3_open("users.db", &db);

    const char* create_table_query =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "email TEXT NOT NULL UNIQUE, "
        "password TEXT NOT NULL);";

    sqlite3_exec(db, create_table_query, nullptr, nullptr, nullptr);
    sqlite3_close(db);
}

// URL decode function
std::string UrlDecode(const std::string& src) {
    std::string decoded;
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%') {
            if (i + 2 < src.size()) {
                std::string hex = src.substr(i + 1, 2);
                int value = 0;
                std::istringstream(hex) >> std::hex >> value;
                decoded += static_cast<char>(value);
                i += 2;
            }
        } else if (src[i] == '+') {
            decoded += ' ';
        } else {
            decoded += src[i];
        }
    }
    return decoded;
}

// Parse credentials from the request body
std::pair<std::string, std::string> ParseCreds(const std::string& text) {
    std::unordered_map<std::string, std::string> params;
    std::istringstream iss(text);
    std::string token;

    while (std::getline(iss, token, '&')) {
        size_t pos = token.find('=');
        if (pos != std::string::npos) {
            std::string key = UrlDecode(token.substr(0, pos));
            std::string value = UrlDecode(token.substr(pos + 1));
            params[key] = value;
        }
    }

    return {params["email"], params["password"]};
}

// Check user credentials
bool checkCredentials(const std::string& email, const std::string& password) {
    sqlite3* db;
    sqlite3_open("users.db", &db);

    const char* sql = "SELECT COUNT(*) FROM users WHERE email = ? AND password = ?;";
    sqlite3_stmt* stmt;
    bool valid = false;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            valid = sqlite3_column_int(stmt, 0) > 0;
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return valid;
}

// Read HTML file content
std::string readHtmlFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file) {
        return "404 Not Found";
    }
    return std::string((std::istreambuf_iterator<char>(file)),
                        (std::istreambuf_iterator<char>()));
}

// Check if the user is logged in
bool isLoggedIn(const crow::request& req) {
    std::string sessionCookie = req.get_header_value("Cookie");
    if (sessionCookie.empty()) {
        return false;
    }

    // Check if the session cookie contains a valid session token
    size_t pos = sessionCookie.find("session=");
    if (pos != std::string::npos) {
        std::string token = sessionCookie.substr(pos + 8); // Length of "session=" is 8
        return activeSessions.find(token) != activeSessions.end();
    }
    return false;
}

// Logout logic
void logoutUser(const std::string& sessionToken) {
    activeSessions.erase(sessionToken);
}

int main() {
    std::srand(std::time(0)); // Seed for random session token generation
    init_db();

    crow::SimpleApp app;

    // Route for index page
    // CROW_ROUTE(app, "/")([](const crow::request& req) {
    //     if (isLoggedIn(req)) {
    //         return crow::response(200, readHtmlFile("../UI-cl/index.html"));
    //     } else {
    //         crow::response res;
    //         res.code = 302;
    //         res.add_header("Location", "/login");
    //         return res;
    //     }
    // });

    CROW_ROUTE(app, "/")([](const crow::request& req) {
        return crow::response(200, readHtmlFile("../UI-cl/index.html"));
    });


    // Route for login page
    CROW_ROUTE(app, "/login")([]() {
        return crow::response(200, readHtmlFile("../UI-cl/login.html"));
    });

    // Route for registration page
    CROW_ROUTE(app, "/register")([]() {
        return crow::response(200, readHtmlFile("../UI-cl/reg.html"));
    });

    // Handle registration
    CROW_ROUTE(app, "/register").methods("POST"_method)([](const crow::request& req) {
        auto body = ParseCreds(req.body);
        std::string email = body.first;
        std::string password = body.second;

        if (email.empty() || password.empty()) {
            return crow::response(400, "Invalid input");
        }

        sqlite3* db;
        sqlite3_open("users.db", &db);

        std::string query = "INSERT INTO users (email, password) VALUES (?, ?)";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);
            rc = sqlite3_step(stmt);
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        if (rc == SQLITE_DONE) {
            // Generate a session token
            std::string sessionToken = generateSessionToken();
            activeSessions[sessionToken] = email;

            crow::response res;
            res.code = 302;
            res.add_header("Set-Cookie", "session=" + sessionToken + "; Path=/");
            res.add_header("Location", "/");  // Redirect back to index page after successful registration
            return res;
        } else {
            return crow::response(400, "Error: Email already in use or other database error.");
        }
    });

    // Handle login
    CROW_ROUTE(app, "/login").methods("POST"_method)([](const crow::request& req) {
        auto body = ParseCreds(req.body);
        std::string email = body.first;
        std::string password = body.second;

        if (email.empty() || password.empty()) {
            return crow::response(400, "Invalid input");
        }

        if (checkCredentials(email, password)) {
            // Generate a session token
            std::string sessionToken = generateSessionToken();
            activeSessions[sessionToken] = email;

            crow::response res;
            res.code = 302;
            res.add_header("Set-Cookie", "session=" + sessionToken + "; Path=/");
            res.add_header("Location", "/");  // Redirect back to index page after successful login
            return res;
        } else {
            return crow::response(400, "Invalid email or password");
        }
    });

    // Handle logout
    CROW_ROUTE(app, "/logout").methods("POST"_method)([](const crow::request& req) {
        // Clear session logic here
        std::string sessionId = req.get_header_value("Cookie");
        
        // Remove the session from your activeSessions map
        if (!sessionId.empty()) {
            // Your logic to erase the session
            activeSessions.erase(sessionId);
        }

        // Clear the session cookie
        crow::response res(200);
        res.set_header("Set-Cookie", "session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/;");
        
        // Do not redirect, just return the index page
        res.body = readHtmlFile("../UI-cl/index.html");
        return res;
    });


    app.port(8080).multithreaded().run();
}
