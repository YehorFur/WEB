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

    const char* create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "email TEXT NOT NULL UNIQUE, "
        "password TEXT NOT NULL);";

    const char* create_tasks_table =
        "CREATE TABLE IF NOT EXISTS tasks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_email TEXT NOT NULL, "
        "matrix TEXT NOT NULL, "
        "response TEXT, "
        "status TEXT NOT NULL DEFAULT 'in process', "
        "FOREIGN KEY (user_email) REFERENCES users (email));";

    sqlite3_exec(db, create_users_table, nullptr, nullptr, nullptr);
    sqlite3_exec(db, create_tasks_table, nullptr, nullptr, nullptr);
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

// Function to save the task result in the database
void saveTaskResult(const std::string& email, const std::vector<std::vector<int>>& matrix, const std::string& response, const std::string& status) {
    sqlite3* db;
    sqlite3_open("users.db", &db);

    // Convert the matrix to a string
    std::ostringstream matrixStream;
    for (const auto& row : matrix) {
        for (size_t i = 0; i < row.size(); ++i) {
            matrixStream << row[i];
            if (i < row.size() - 1) matrixStream << ",";
        }
        matrixStream << ";"; // Separate rows with ';'
    }
    std::string matrixString = matrixStream.str();

    const char* sql = "INSERT INTO tasks (user_email, matrix, response, status) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, matrixString.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, response.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, status.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
}

void modifyTaskResult(const std::string& email, const std::vector<std::vector<int>>& matrix, const std::string& response, const std::string& status) {
    sqlite3* db;
    sqlite3_open("users.db", &db);

    // Convert the matrix to a string (same format used for task storage)
    std::ostringstream matrixStream;
    for (const auto& row : matrix) {
        for (size_t i = 0; i < row.size(); ++i) {
            matrixStream << row[i];
            if (i < row.size() - 1) matrixStream << ",";
        }
        matrixStream << ";"; // Separate rows with ';'
    }
    std::string matrixString = matrixStream.str();

    // Use an UPDATE statement to modify response and status for the specified email and matrix
    const char* sql = "UPDATE tasks SET response = ?, status = ? WHERE user_email = ? AND matrix = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, response.c_str(), -1, SQLITE_STATIC);       // Bind response
        sqlite3_bind_text(stmt, 2, status.c_str(), -1, SQLITE_STATIC);         // Bind status
        sqlite3_bind_text(stmt, 3, email.c_str(), -1, SQLITE_STATIC);          // Bind email
        sqlite3_bind_text(stmt, 4, matrixString.c_str(), -1, SQLITE_STATIC);   // Bind matrix as string

        // Execute the update statement and check if it affected any rows
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            std::cout << "Task updated successfully.\n";
        } else {
            std::cerr << "Failed to update task.\n";
        }

        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Failed to prepare statement.\n";
    }

    sqlite3_close(db);
}

// Global variable to keep track of the last used worker
int lastUsedWorker = 0; // Start with the first worker

std::string sendMatrixToWorker(const std::vector<std::vector<int>>& matrix, std::string email) {
    CURL* curl;
    CURLcode res;
    std::string response = "";
    std::string matrixstr;

    // Save the task result in the database
    saveTaskResult(email, matrix, response, "in process");

    // Determine the URL of the worker to send the request to
    std::string workerUrl = (lastUsedWorker % 2 == 0) ? "http://localhost:8081/solve_tsp" : "http://localhost:8082/solve_tsp";
    
    // Update the counter for the next request
    lastUsedWorker++;

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
        curl_easy_setopt(curl, CURLOPT_URL, workerUrl.c_str());
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
            modifyTaskResult(email, matrix, response, "Done");
        }

        // Cleanup
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return response;
}

void cancelTask(const std::string& email) {
    sqlite3* db;
    sqlite3_open("users.db", &db);

    const char* sql = "UPDATE tasks SET status = 'canceled' WHERE user_email = ? AND status = 'in process';"; // You may want to add more conditions here to specify which task to cancel
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
}

std::string fetchUserTaskHistory(const std::string& email) {
    sqlite3* db;
    int rc = sqlite3_open("users.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return "<p>Error opening database.</p>"; // Return error message
    }

    const char* query = "SELECT id, matrix, response, status FROM tasks WHERE user_email = ?";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return "<p>Error preparing statement.</p>"; // Return error message
    }

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);

    std::stringstream historyHtml;
    historyHtml << "<table class='task-history'><tr><th>ID</th><th>Matrix</th><th>Response</th><th>Status</th></tr>";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        historyHtml << "<tr>";
        historyHtml << "<td>" << sqlite3_column_int(stmt, 0) << "</td>";
        historyHtml << "<td>" << sqlite3_column_text(stmt, 1) << "</td>";
        historyHtml << "<td>" << sqlite3_column_text(stmt, 2) << "</td>";
        historyHtml << "<td>" << sqlite3_column_text(stmt, 3) << "</td>";
        historyHtml << "</tr>";
    }

    historyHtml << "</table>";

    std::cout<<historyHtml.str()<< " " << email<<std::endl;

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return historyHtml.str();
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
            res.add_header("Set-Cookie", "session=" + sessionToken + "; Path=/"); // HttpOnly for security
            //res.add_header("Set-Cookie", "email=" + email + "; Path=/; HttpOnly;"); // Store email separately
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

    // Modify the /matrix route handler
    CROW_ROUTE(app, "/matrix").methods("POST"_method)([](const crow::request& req) {
        crow::ci_map headers = req.headers;
        std::string body = req.body;
        std::vector<std::vector<int>> matrix;
        std::string email;

        for(auto it : headers){
            size_t start = it.second.find("email=") + 6;  // Move past "email="
            size_t end = it.second.find(";", start);      // Find the semicolon after the email
            
            // Extract the email substring
            if (start != std::string::npos && end != std::string::npos) {
                email = it.second.substr(start, end - start);
            }
        }
        
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

        // Send matrix to worker and get response
        std::string response = sendMatrixToWorker(matrix, email);

        return crow::response(200, response);
    });

    
    CROW_ROUTE(app, "/fetch_history").methods("POST"_method)([](const crow::request& req) {
        crow::ci_map headers = req.headers;
        std::string email;

        // Extract email from headers
        for (const auto& header : headers) {
            size_t start = header.second.find("email=") + 6;  // Position after "email="
            size_t end = header.second.find(";", start);      // Semicolon after the email
            
            if (header.second.find("email=") != std::string::npos && end != std::string::npos) {
                email = header.second.substr(start, end - start);
                break;  // Email found, no need to continue looping
            }
        }

        return crow::response(200, fetchUserTaskHistory(email));  // Return the response containing the HTML table
    });


    CROW_ROUTE(app, "/cancel-task").methods("POST"_method)([](const crow::request& req) {
        // Check if the user is logged in
        if (!isLoggedIn(req)) {
            return crow::response(403, "Unauthorized");
        }

        std::string sessionCookie = req.get_header_value("Cookie");
        size_t pos = sessionCookie.find("session=");
        std::string sessionToken = sessionCookie.substr(pos + 8); // Extract the session token

        // Extract email from activeSessions using sessionToken
        std::string email = activeSessions[sessionToken];

        // Cancel the task in the database
        cancelTask(email);

        std::string response_message = "Task has been canceled successfully.";
        return crow::response(200, response_message); // Respond with success message
    });


    app.port(8080).multithreaded().run();
    return 0;
}
