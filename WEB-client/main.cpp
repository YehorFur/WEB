#include "crow.h"
#include <sqlite3.h>
#include <unordered_map>
#include <sstream>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <curl/curl.h>

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

// Base64 encoding
std::string Base64Encode(const std::string& decoded) {
    // Calculate the size needed for the encoded output
    const auto encoded_size = boost::beast::detail::base64::encoded_size(decoded.size());

    // Prepare the output string with the required size and initialize it with null characters
    std::string encoded_output(encoded_size, '\0');

    // Perform the encoding
    boost::beast::detail::base64::encode(encoded_output.data(), decoded.data(), decoded.size());

    // Return the Base64 encoded string
    return encoded_output;
}

// Base64 decoding
std::string Base64Decode(const std::string& encoded) {
    // Calculate the size needed for the decoded output
    const auto decoded_size = boost::beast::detail::base64::decoded_size(encoded.size());
    std::string decoded_output(decoded_size, '\0');

    // Decode the Base64 encoded string
    const auto [decoded_length, success] =
        boost::beast::detail::base64::decode(decoded_output.data(), encoded.data(), encoded.size());

    // Resize the decoded output to the actual length of decoded data
    decoded_output.resize(decoded_length);

    return decoded_output;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Callback function to handle response data
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

std::string sendMatrixToWorker(const std::vector<std::vector<int>>& matrix) {
    CURL* curl;
    CURLcode res;
    std::string response;

    // Initialize cURL
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (curl) {
        // Create matrix string for POST request
        std::string matrixData;
        for (const auto& row : matrix) {
            for (size_t i = 0; i < row.size(); ++i) {
                matrixData += std::to_string(row[i]);
                if (i < row.size() - 1) matrixData += ",";
            }
            matrixData += "&"; // Separate rows with '&'
        }
        matrixData.pop_back(); // Remove last '&'

        // Set options for the POST request
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8081/solve_tsp");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, matrixData.c_str());

        // Set the write callback function to capture the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response); // Pass the response string

        // Perform the request
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            response = "Error: " + std::string(curl_easy_strerror(res));
        } else {
            // The response should now contain the result from the worker
            response = "TSP solved successfully! Response: " + response; // Include worker's response
        }

        // Cleanup
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return response;
}

int main() {
    std::srand(std::time(0)); // Seed for random session token generation
    init_db();

    crow::SimpleApp app;

    // Route for index page
    CROW_ROUTE(app, "/")([](const crow::request& req) {
        if (!isLoggedIn(req)) {
            return crow::response(401, readHtmlFile("../UI-cl/login.html"));
        }
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

        std::string encodedPassword = Base64Encode(password); // Encode the password
        std::string query = "INSERT INTO users (email, password) VALUES (?, ?)";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, encodedPassword.c_str(), -1, SQLITE_STATIC); // Save the encoded password
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

        if (checkCredentials(email, Base64Encode(password))) { // Check against encoded password
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
        if (!isLoggedIn(req)) {
            return crow::response(401, "Unauthorized");
        }

        std::string sessionCookie = req.get_header_value("Cookie");
        size_t pos = sessionCookie.find("session=");
        std::string sessionToken = sessionCookie.substr(pos + 8); // Extract the session token

        logoutUser(sessionToken);
        crow::response res;
        res.code = 302;
        res.add_header("Set-Cookie", "session=; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
        res.add_header("Location", "/");  // Redirect back to index page after logout
        return res;
    });

    // Handle matrix processing
    CROW_ROUTE(app, "/matrix").methods("POST"_method)([](const crow::request& req) {
        std::string body = req.body;
        std::vector<std::vector<int>> matrix;

        // Split the body by '&' to get each row
        std::vector<std::string> rows = split(body, '&');

        for (const std::string& row : rows) {
            // Split each row by ',' to get individual numbers
            std::vector<std::string> numbers = split(row, ',');

            std::vector<int> matrixRow;
            for (const std::string& num : numbers) {
                matrixRow.push_back(std::stoi(num)); // Convert string to int
            }
            matrix.push_back(matrixRow); // Add row to the matrix
        }

        // for (auto it : matrix){
        //     for ( auto itt : it){
        //         std::cout<< itt << " ";
        //     }
        //     std::cout<<std::endl;
        // }

        // You can perform operations on the matrix here
        std::string response = sendMatrixToWorker(matrix);

        //std::cout << response << std::endl;

        return crow::response(200, response);
    });

    app.port(8080).multithreaded().run();
    return 0;
}
