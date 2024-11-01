#include "crow.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <numeric>

// Function to calculate the TSP solution (a simple brute-force method for demonstration)
int tsp(const std::vector<std::vector<int>>& graph) {
    int n = graph.size();
    std::vector<int> path(n);
    std::iota(path.begin(), path.end(), 0); // Fill with 0, 1, ..., n-1

    int minCost = INT_MAX;

    do {
        int currentCost = 0;
        for (int i = 0; i < n; i++) {
            currentCost += graph[path[i]][path[(i + 1) % n]];
        }
        minCost = std::min(minCost, currentCost);
    } while (std::next_permutation(path.begin(), path.end()));

    return minCost;
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

int main(int argc, char* argv[]) {
    crow::SimpleApp workerApp;

    // Check if a port number is provided
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1; // Exit with an error code
    }

    // Convert the port argument from string to integer
    int port = std::stoi(argv[1]);

    // Route to solve TSP
    CROW_ROUTE(workerApp, "/solve_tsp").methods("POST"_method)([](const crow::request& req) {
        // Parse the incoming matrix
        std::string body = req.body;
        std::vector<std::vector<int>> matrix;
        std::vector<std::string> rows = split(body, '&');

        for (const std::string& row : rows) {
            std::vector<std::string> numbers = split(row, ',');
            std::vector<int> matrixRow;
            for (const std::string& num : numbers) {
                matrixRow.push_back(std::stoi(num));
            }
            matrix.push_back(matrixRow);
        }

        // Solve the TSP
        int cost = tsp(matrix);
        return crow::response(200, "Minimum cost: " + std::to_string(cost) + "\n");
    });

    workerApp.port(port).run(); // Set the port from command-line argument
    return 0;
}
