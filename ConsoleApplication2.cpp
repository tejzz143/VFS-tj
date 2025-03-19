#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <deque>
#include <algorithm>
#include <conio.h>
#include <windows.h>
#include <ctime>
#include <functional> // For std::hash
#pragma warning(disable: 4996)

namespace fs = std::filesystem;

// Configuration file path in the user's appdata folder
const fs::path CONFIG_FILE_PATH = fs::path(getenv("APPDATA")) / "VFS_Cpp" / "config.txt";

// Simple hash function for passwords
std::string hashPassword(const std::string& password) {
    std::hash<std::string> hasher;
    return std::to_string(hasher(password));
}

struct User {
    std::string username;
    std::string passwordHash;
    bool isAdmin = false;
    std::time_t creationTime;
    std::time_t lastLogin;
};

class VFS {
public:
    struct File {
        std::string name;
        std::string content;
        std::string owner;
        std::time_t creationTime;
        std::time_t modificationTime;
        bool isReadOnly = false;
    };

    struct Directory {
        std::unordered_map<std::string, File> files;
        std::unordered_map<std::string, Directory> subdirectories;
        std::string owner;
        std::time_t creationTime;
    };

    Directory root;
    Directory* currentDir = &root;
    std::deque<Directory*> pathStack{ &root };
    fs::path vfsRoot;
    fs::path currentPath;
    fs::path userHomePath;

    // User management
    std::unordered_map<std::string, User> users;
    User* currentUser = nullptr;
    bool isAuthenticated = false;

    VFS() {
        // Check if configuration exists
        if (!loadConfiguration()) {
            // If not, prompt for directory and save it
            promptForDirectory();
        }

        // Initialize VFS with the configured root
        currentPath = vfsRoot;

        // Ensure the VFS root directory exists
        if (!fs::exists(vfsRoot)) {
            try {
                fs::create_directories(vfsRoot);
                std::cout << "Created VFS root directory at: " << vfsRoot << std::endl;
            }
            catch (const fs::filesystem_error& e) {
                std::cerr << "Error creating VFS root: " << e.what() << std::endl;
            }
        }

        // Setup system directories
        setupSystemDirectories();

        // Load users from etc/passwd
        loadUsers();

        // Load the file system
        loadVFS(vfsRoot, root);

        // Try to authenticate
        authenticate();
    }

    bool CreateJunction(const std::string& targetPath, const std::string& junctionPath) {
        // Convert paths to wide strings (Windows API requires wide strings)
        std::wstring wTargetPath(targetPath.begin(), targetPath.end());
        std::wstring wJunctionPath(junctionPath.begin(), junctionPath.end());

        // Create the junction
        if (CreateSymbolicLink(wJunctionPath.c_str(), wTargetPath.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY)) {
            std::cout << "Junction created successfully: " << junctionPath << " -> " << targetPath << "\n";
            return true;
        }
        else {
            DWORD error = GetLastError();
            std::cerr << "Failed to create junction: Error " << error << "\n";

            // Provide a user-friendly error message
            switch (error) {
            case ERROR_PRIVILEGE_NOT_HELD:
                std::cerr << "Administrative privileges are required to create a junction.\n";
                break;
            case ERROR_ALREADY_EXISTS:
                std::cerr << "The junction or directory already exists.\n";
                break;
            default:
                std::cerr << "An unknown error occurred.\n";
                break;
            }

            return false;
        }
    }

    void setupSystemDirectories() {
        // Create system directories (similar to Linux)
        fs::path etcPath = vfsRoot / "etc";
        fs::path homeDir = vfsRoot / "home";
        fs::path guestDir = vfsRoot / "guest";
        fs::path sharedDir = vfsRoot / "shared"; // Shared directory

        try {
            // Create etc directory for system files
            if (!fs::exists(etcPath)) {
                fs::create_directories(etcPath);
            }

            // Create user password file (like /etc/passwd)
            fs::path passwdFile = etcPath / "passwd";
            if (!fs::exists(passwdFile)) {
                std::ofstream passwd(passwdFile);
                if (passwd) {
                    // Add root user by default
                    passwd << "root:" << hashPassword("admin") << ":1:1:" << std::time(nullptr) << "\n";
                    std::cout << "Created default 'root' user with password 'admin'\n";
                }
                passwd.close();
            }

            // Create home directory
            if (!fs::exists(homeDir)) {
                fs::create_directories(homeDir);
            }

            // Create guest directory
            if (!fs::exists(guestDir)) {
                fs::create_directories(guestDir);
            }

            // Create shared directory
            if (!fs::exists(sharedDir)) {
                fs::create_directories(sharedDir);
                std::cout << "Created shared directory at: " << sharedDir << std::endl;
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Error setting up system directories: " << e.what() << std::endl;
        }
    }

    void loadUsers() {
        fs::path passwdFile = vfsRoot / "etc" / "passwd";

        if (fs::exists(passwdFile)) {
            std::ifstream file(passwdFile);
            if (file) {
                std::string line;
                while (std::getline(file, line)) {
                    std::istringstream iss(line);
                    std::string username, passwordHash, isAdminStr, dummy;
                    std::time_t creationTime = 0;
                    std::time_t lastLogin = 0;

                    // Format: username:passwordHash:isAdmin:dummy:creationTime:lastLogin
                    std::getline(iss, username, ':');
                    std::getline(iss, passwordHash, ':');
                    std::getline(iss, isAdminStr, ':');
                    std::getline(iss, dummy, ':');

                    // Parse creation time
                    std::string creationTimeStr;
                    if (std::getline(iss, creationTimeStr, ':')) {
                        try {
                            creationTime = std::stoll(creationTimeStr);
                        }
                        catch (...) {
                            creationTime = std::time(nullptr);
                        }
                    }

                    // Parse last login time (if present)
                    std::string lastLoginStr;
                    if (std::getline(iss, lastLoginStr)) {
                        try {
                            lastLogin = std::stoll(lastLoginStr);
                        }
                        catch (...) {
                            lastLogin = 0;
                        }
                    }

                    // Create user
                    User user;
                    user.username = username;
                    user.passwordHash = passwordHash;
                    user.isAdmin = (isAdminStr == "1");
                    user.creationTime = creationTime;
                    user.lastLogin = lastLogin;

                    users[username] = user;
                }
            }
        }

        // Ensure root user exists
        if (users.find("root") == users.end()) {
            User rootUser;
            rootUser.username = "root";
            rootUser.passwordHash = hashPassword("admin");
            rootUser.isAdmin = true;
            rootUser.creationTime = std::time(nullptr);
            rootUser.lastLogin = 0;

            users["root"] = rootUser;
            saveUsers();
        }
    }

    void saveUsers() {
        fs::path passwdFile = vfsRoot / "etc" / "passwd";

        try {
            std::ofstream file(passwdFile);
            if (file) {
                for (const auto& [username, user] : users) {
                    // Format: username:passwordHash:isAdmin:dummy:creationTime:lastLogin
                    file << user.username << ":"
                        << user.passwordHash << ":"
                        << (user.isAdmin ? "1" : "0") << ":"
                        << "x" << ":"
                        << user.creationTime << ":"
                        << user.lastLogin << "\n";
                }
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Error saving users: " << e.what() << std::endl;
        }
    }

    bool authenticate() {
        // Clear the console
        system("cls");

        // Display header
        std::cout << "\033[1;36m========================================================\033[0m\n";
        std::cout << "\033[1;33m                   VFS LOGIN SYSTEM\033[0m\n";
        std::cout << "\033[1;36m========================================================\033[0m\n\n";

        std::cout << "Enter username (or 'guest' for guest access, or 'exit' to quit): ";
        std::string username;
        std::getline(std::cin, username);

        if (username == "exit") {
            exit(0);
        }

        if (username == "guest") {
            std::cout << "Logging in as guest...\n";

            // Set up guest session
            isAuthenticated = true;
            currentUser = nullptr;

            // Set current directory to guest directory
            navigateToPath(vfsRoot / "guest");

            std::cout << "Guest login successful. You are in the guest directory.\n";
            std::cout << "Press Enter to continue...";
            std::cin.get();

            // Clear the console after guest login
            system("cls");
            return true;
        }

        // Check if user exists
        if (users.find(username) == users.end()) {
            std::cout << "User '" << username << "' does not exist.\n";
            std::cout << "Would you like to create a new user? (y/n): ";
            char choice;
            std::cin >> choice;
            std::cin.ignore();

            if (choice == 'y' || choice == 'Y') {
                return createUser(username);
            }

            return false;
        }

        // Ask for password
        std::cout << "Password: ";
        std::string password;

        // Simple password masking with asterisks
        char ch;
        while ((ch = _getch()) != 13) { // 13 is Enter key
            if (ch == 8) { // Backspace
                if (!password.empty()) {
                    password.pop_back();
                    std::cout << "\b \b"; // Erase character from screen
                }
            }
            else if (ch >= 32 && ch <= 126) { // Printable characters
                password.push_back(ch);
                std::cout << "*";
            }
        }
        std::cout << std::endl;

        // Validate password
        std::string hashedPassword = hashPassword(password);
        if (users[username].passwordHash == hashedPassword) {
            // Update last login time
            users[username].lastLogin = std::time(nullptr);
            saveUsers();

            // Set current user
            currentUser = &users[username];
            isAuthenticated = true;

            // Navigate to the user's home directory
            ensureUserHomeDirectory(username);
            navigateToPath(vfsRoot / "home" / username);

            std::cout << "Login successful. Welcome, " << username << "!\n";
            std::cout << "Press Enter to continue...";
            std::cin.get();

            // Clear the console after successful login
            system("cls");
            return true;
        }
        else {
            std::cout << "Invalid password. Login failed.\n";
            std::cout << "Press Enter to try again...";
            std::cin.get();
            return false;
        }
    }

    bool createUser(const std::string& username) {
        if (username.empty() || username == "guest") {
            std::cout << "Invalid username. Cannot be empty or 'guest'.\n";
            return false;
        }

        std::cout << "Creating new user '" << username << "'...\n";

        // Ask for password
        std::string password, confirmPassword;
        bool passwordsMatch = false;

        do {
            std::cout << "Enter password: ";
            char ch;
            password.clear();
            while ((ch = _getch()) != 13) { // 13 is Enter key
                if (ch == 8) { // Backspace
                    if (!password.empty()) {
                        password.pop_back();
                        std::cout << "\b \b"; // Erase character from screen
                    }
                }
                else if (ch >= 32 && ch <= 126) { // Printable characters
                    password.push_back(ch);
                    std::cout << "*";
                }
            }
            std::cout << std::endl;

            std::cout << "Confirm password: ";
            confirmPassword.clear();
            while ((ch = _getch()) != 13) {
                if (ch == 8) {
                    if (!confirmPassword.empty()) {
                        confirmPassword.pop_back();
                        std::cout << "\b \b";
                    }
                }
                else if (ch >= 32 && ch <= 126) {
                    confirmPassword.push_back(ch);
                    std::cout << "*";
                }
            }
            std::cout << std::endl;

            if (password != confirmPassword) {
                std::cout << "Passwords do not match. Please try again.\n";
            }
            else {
                passwordsMatch = true;
            }
        } while (!passwordsMatch);

        // Ask if admin user
        bool isAdmin = false;
        if (isAuthenticated && currentUser && currentUser->isAdmin) {
            std::cout << "Make this user an administrator? (y/n): ";
            char choice;
            std::cin >> choice;
            std::cin.ignore();
            isAdmin = (choice == 'y' || choice == 'Y');
        }

        // Create user
        User newUser;
        newUser.username = username;
        newUser.passwordHash = hashPassword(password);
        newUser.isAdmin = isAdmin;
        newUser.creationTime = std::time(nullptr);
        newUser.lastLogin = std::time(nullptr);

        users[username] = newUser;
        saveUsers();

        // Create user home directory
        ensureUserHomeDirectory(username);

        loadVFS(vfsRoot, root);

        std::cout << "User '" << username << "' created successfully.\n";

        // Set as current user
        currentUser = &users[username];
        isAuthenticated = true;

        // Navigate to user's home directory
        navigateToPath(vfsRoot / "home" / username);

        std::cout << "Press Enter to continue...";
        std::cin.get();
        return true;
    }

    void ensureUserHomeDirectory(const std::string& username) {
        fs::path userHome = vfsRoot / "home" / username;
        fs::path sharedDir = vfsRoot / "shared";

        try {
            // Ensure the /home directory exists in the host file system
            if (!fs::exists(userHome.parent_path())) {
                std::cout << "Creating parent directory: " << userHome.parent_path() << "\n";
                fs::create_directories(userHome.parent_path());
            }

            // Create the user's home directory in the host file system
            if (!fs::exists(userHome)) {
                std::cout << "Creating home directory for user '" << username << "' at: " << userHome << "\n";
                fs::create_directories(userHome);
                std::cout << "Home directory created successfully.\n";
            }

            // Create a directory junction to the shared directory
            fs::path sharedLink = userHome / "shared";
            if (!fs::exists(sharedLink)) {
                if (CreateJunction(sharedDir.string(), sharedLink.string())) {
                    std::cout << "Created shared directory junction in user's home directory.\n";
                }
                else {
                    std::cerr << "Failed to create shared directory junction.\n";
                }
            }

            // Update the VFS in-memory structure
            Directory* tempDir = &root;
            for (const auto& part : fs::relative(userHome, vfsRoot)) {
                std::string dirName = part.string();
                if (tempDir->subdirectories.find(dirName) == tempDir->subdirectories.end()) {
                    // Create the directory in the VFS structure
                    Directory newDir;
                    newDir.owner = username;
                    newDir.creationTime = std::time(nullptr);
                    tempDir->subdirectories[dirName] = newDir;
                }
                tempDir = &tempDir->subdirectories[dirName];
            }

            // Create a welcome file in the user's home directory
            fs::path welcomeFile = userHome / "welcome.txt";
            std::ofstream file(welcomeFile);
            if (file) {
                file << "Welcome to your home directory, " << username << "!\n\n";
                file << "This is your personal space in the Virtual File System.\n";
                file << "Feel free to create and manage your files here.\n\n";
                file << "Type 'help' at the VFS prompt to see available commands.\n";
            }
            else {
                std::cerr << "Failed to create welcome file for user '" << username << "'.\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Error creating user home directory: " << e.what() << std::endl;
        }
    }

    void navigateToPath(const fs::path& path) {
        // Reset to root
        currentDir = &root;
        pathStack.clear();
        pathStack.push_back(currentDir);
        currentPath = vfsRoot;

        // Get relative path from VFS root
        fs::path relativePath = fs::relative(path, vfsRoot);

        if (relativePath.empty() || relativePath == ".") {
            return; // Already at root
        }

        // Navigate through each component
        for (const auto& component : relativePath) {
            std::string dirName = component.string();

            if (currentDir->subdirectories.find(dirName) != currentDir->subdirectories.end()) {
                currentDir = &currentDir->subdirectories[dirName];
                pathStack.push_back(currentDir);
                currentPath /= dirName;
            }
            else {
                // If directory doesn't exist in VFS, check if it exists on the host file system
                fs::path dirPath = currentPath / dirName;
                if (fs::exists(dirPath) && fs::is_directory(dirPath)) {
                    // Create the directory in the VFS structure
                    Directory newDir;
                    newDir.owner = currentUser ? currentUser->username : "guest";
                    newDir.creationTime = std::time(nullptr);
                    currentDir->subdirectories[dirName] = newDir;

                    // Navigate to the new directory
                    currentDir = &currentDir->subdirectories[dirName];
                    pathStack.push_back(currentDir);
                    currentPath /= dirName;
                }
                else {
                    std::cerr << "Error navigating to path: Directory '" << dirName << "' not found.\n";
                    return;
                }
            }
        }
    }

    void changePassword(const std::string& username) {
        if (!currentUser || (currentUser->username != username && !currentUser->isAdmin)) {
            std::cerr << "Permission denied: You cannot change this user's password.\n";
            return;
        }

        std::string newPassword, confirmPassword;
        bool passwordsMatch = false;

        do {
            std::cout << "Enter new password: ";
            char ch;
            newPassword.clear();
            while ((ch = _getch()) != 13) { // 13 is Enter key
                if (ch == 8) { // Backspace
                    if (!newPassword.empty()) {
                        newPassword.pop_back();
                        std::cout << "\b \b"; // Erase character from screen
                    }
                }
                else if (ch >= 32 && ch <= 126) { // Printable characters
                    newPassword.push_back(ch);
                    std::cout << "*";
                }
            }
            std::cout << std::endl;

            std::cout << "Confirm new password: ";
            confirmPassword.clear();
            while ((ch = _getch()) != 13) {
                if (ch == 8) {
                    if (!confirmPassword.empty()) {
                        confirmPassword.pop_back();
                        std::cout << "\b \b";
                    }
                }
                else if (ch >= 32 && ch <= 126) {
                    confirmPassword.push_back(ch);
                    std::cout << "*";
                }
            }
            std::cout << std::endl;

            if (newPassword != confirmPassword) {
                std::cout << "Passwords do not match. Please try again.\n";
            }
            else {
                passwordsMatch = true;
            }
        } while (!passwordsMatch);

        // Update password hash
        users[username].passwordHash = hashPassword(newPassword);
        saveUsers();

        std::cout << "Password for user '" << username << "' changed successfully.\n";
    }

    bool loadConfiguration() {
        // Check if config directory exists, if not create it
        fs::path configDir = CONFIG_FILE_PATH.parent_path();
        if (!fs::exists(configDir)) {
            try {
                fs::create_directories(configDir);
            }
            catch (const fs::filesystem_error& e) {
                std::cerr << "Error creating config directory: " << e.what() << std::endl;
                return false;
            }
        }

        // Try to read the configuration file
        if (fs::exists(CONFIG_FILE_PATH)) {
            std::ifstream configFile(CONFIG_FILE_PATH);
            if (configFile) {
                std::string path;
                std::getline(configFile, path);

                // Validate the path
                if (!path.empty() && fs::exists(path)) {
                    vfsRoot = path;
                    return true;
                }
            }
        }

        return false;
    }

    void saveConfiguration() {
        try {
            // Create the config directory if it doesn't exist
            fs::path configDir = CONFIG_FILE_PATH.parent_path();
            if (!fs::exists(configDir)) {
                fs::create_directories(configDir);
            }

            // Save the VFS root path to the config file
            std::ofstream configFile(CONFIG_FILE_PATH);
            if (configFile) {
                configFile << vfsRoot.string();
            }
            else {
                std::cerr << "Failed to write configuration file." << std::endl;
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Error saving configuration: " << e.what() << std::endl;
        }
    }

    void promptForDirectory() {
        std::string path;
        bool validPath = false;

        while (!validPath) {
            // Clear the console
            system("cls");

            std::cout << "\033[1;33m========================================================\033[0m\n";
            std::cout << "\033[1;36m           FIRST TIME SETUP - DIRECTORY MOUNTING\033[0m\n";
            std::cout << "\033[1;33m========================================================\033[0m\n\n";

            std::cout << "Please specify the directory path to mount as your Virtual File System:\n";
            std::cout << "(e.g., C:\\MyVFS or D:\\Documents\\VFS)\n\n";
            std::cout << "\033[1;32mPath: \033[0m";

            std::getline(std::cin, path);

            // Trim whitespace
            path.erase(0, path.find_first_not_of(" \t\n\r\f\v"));
            path.erase(path.find_last_not_of(" \t\n\r\f\v") + 1);

            // Use default path if empty
            if (path.empty()) {
                fs::path defaultPath = fs::path(getenv("USERPROFILE")) / "VFS_Cpp";
                path = defaultPath.string();
                std::cout << "\nUsing default path: " << path << std::endl;
                std::cout << "Press Enter to continue...";
                std::cin.get();
            }

            try {
                // Check if the path exists, if not try to create it
                if (!fs::exists(path)) {
                    std::cout << "\nDirectory does not exist. Create it? (y/n): ";
                    char choice;
                    std::cin >> choice;
                    std::cin.ignore(); // Clear the newline character

                    if (choice == 'y' || choice == 'Y') {
                        fs::create_directories(path);
                        std::cout << "Directory created successfully.\n";
                    }
                    else {
                        std::cout << "Please specify a different path.\n";
                        std::cout << "Press Enter to continue...";
                        std::cin.get();
                        continue;
                    }
                }

                // Validate that it's a directory
                if (fs::is_directory(path)) {
                    vfsRoot = path;
                    validPath = true;

                    // Save the configuration
                    saveConfiguration();

                    std::cout << "\nDirectory mounted successfully: " << vfsRoot << std::endl;
                    std::cout << "This directory will be used in future sessions.\n";
                    std::cout << "Press Enter to continue...";
                    std::cin.get();
                }
                else {
                    std::cout << "\nError: The specified path is not a directory.\n";
                    std::cout << "Press Enter to continue...";
                    std::cin.get();
                }
            }
            catch (const fs::filesystem_error& e) {
                std::cerr << "\nError: " << e.what() << std::endl;
                std::cout << "Press Enter to continue...";
                std::cin.get();
            }
        }
    }

    void loadVFS(const fs::path& path, Directory& dir) {
        try {
            // Set directory creation time
            if (fs::exists(path)) {
                auto fileTime = fs::last_write_time(path);
                auto systemTime = std::chrono::clock_cast<std::chrono::system_clock>(fileTime);
                dir.creationTime = std::chrono::system_clock::to_time_t(systemTime);
            }
            else {
                dir.creationTime = std::time(nullptr);
            }

            // Set directory owner
            dir.owner = determineOwner(path);

            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.is_directory()) {
                    std::string dirname = entry.path().filename().string();
                    dir.subdirectories[dirname] = Directory();
                    loadVFS(entry.path(), dir.subdirectories[dirname]);
                }
                else if (entry.is_regular_file()) {
                    std::string filename = entry.path().filename().string();
                    std::ifstream file(entry.path(), std::ios::binary);  // Use binary mode
                    if (file) {
                        std::stringstream buffer;
                        buffer << file.rdbuf();

                        File newFile;
                        newFile.name = filename;
                        newFile.content = buffer.str();
                        newFile.owner = determineOwner(entry.path());

                        // Get file timestamps
                        auto writeTime = fs::last_write_time(entry.path());
                        auto createTime = fs::last_write_time(entry.path());
                        auto writeTimeSystem = std::chrono::clock_cast<std::chrono::system_clock>(writeTime);
                        auto createTimeSystem = std::chrono::clock_cast<std::chrono::system_clock>(createTime);

                        newFile.creationTime = std::chrono::system_clock::to_time_t(createTimeSystem);
                        newFile.modificationTime = std::chrono::system_clock::to_time_t(writeTimeSystem);

                        dir.files[filename] = newFile;
                    }
                    else {
                        std::cerr << "Error opening file: " << entry.path() << std::endl;
                    }
                }
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Error loading VFS: " << e.what() << std::endl;
        }
    }

    std::string determineOwner(const fs::path& path) {
        // This is a simple implementation for file ownership
        // In a real system, you would retrieve this from the filesystem or a database

        // Check if the path is within a user's home directory
        fs::path relativePath = fs::relative(path, vfsRoot);
        std::string pathStr = relativePath.string();

        // Replace backslashes with forward slashes for consistent parsing
        std::replace(pathStr.begin(), pathStr.end(), '\\', '/');

        if (pathStr.find("home/") == 0) {
            // Extract username from path (e.g., "home/username/...")
            std::istringstream iss(pathStr.substr(5)); // Skip "home/"
            std::string username;
            std::getline(iss, username, '/');

            if (!username.empty() && users.find(username) != users.end()) {
                return username;
            }
        }
        else if (pathStr.find("guest/") == 0) {
            return "guest";
        }
        else if (pathStr.find("etc/") == 0) {
            return "root";
        }

        // Default owner is root
        return "root";
    }

    bool checkPermission(const std::string& path, bool writeAccess = false) {
        // Guest can only access guest directory
        if (!currentUser) {
            fs::path relativePath = fs::relative(currentPath / path, vfsRoot);
            std::string pathStr = relativePath.string();
            std::replace(pathStr.begin(), pathStr.end(), '\\', '/');

            // Guest cannot modify files, only read
            if (writeAccess) {
                return false;
            }

            // Check if in guest directory
            return pathStr.find("guest/") == 0 || pathStr == "guest";
        }

        // Root/admin can do anything
        if (currentUser->isAdmin) {
            return true;
        }

        // Regular users can access their home directory and the guest directory
        fs::path fullPath = currentPath / path;
        fs::path relativePath = fs::relative(fullPath, vfsRoot);
        std::string pathStr = relativePath.string();
        std::replace(pathStr.begin(), pathStr.end(), '\\', '/');

        // Check if in user's home directory
        std::string userHomePrefix = "home/" + currentUser->username + "/";
        if (pathStr.find(userHomePrefix) == 0 || pathStr == "home/" + currentUser->username) {
            return true;
        }

        // Check if in guest directory (read-only for regular users)
        if (pathStr.find("guest/") == 0 || pathStr == "guest") {
            return !writeAccess; // Can read but not write
        }

        // Users can't access other users' home directories or system files
        return false;
    }

    void createFile(const std::string& name, const std::string& content = "") {
        if (name.empty()) {
            std::cerr << "Error: File name cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(name, true)) {
            std::cerr << "Permission denied: Cannot create file in this location.\n";
            return;
        }

        fs::path filePath = currentPath / name;
        try {
            std::ofstream file(filePath, std::ios::binary);  // Use binary mode
            if (file) {
                file << content;

                File newFile;
                newFile.name = name;
                newFile.content = content;
                newFile.owner = currentUser ? currentUser->username : "guest";
                newFile.creationTime = std::time(nullptr);
                newFile.modificationTime = std::time(nullptr);

                currentDir->files[name] = newFile;
                std::cout << "File '" << name << "' created in VFS at " << filePath << "\n";
            }
            else {
                std::cerr << "Failed to create file: Could not open file for writing.\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Failed to create file: " << e.what() << std::endl;
        }
    }

    void createDirectory(const std::string& name) {
        if (name.empty()) {
            std::cerr << "Error: Directory name cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(name, true)) {
            std::cerr << "Permission denied: Cannot create directory in this location.\n";
            return;
        }

        fs::path dirPath = currentPath / name;
        try {
            if (fs::create_directory(dirPath)) {
                Directory newDir;
                newDir.owner = currentUser ? currentUser->username : "guest";
                newDir.creationTime = std::time(nullptr);

                currentDir->subdirectories[name] = newDir;
                std::cout << "Directory '" << name << "' created in VFS at " << dirPath << "\n";
            }
            else {
                std::cerr << "Failed to create directory: Could not create directory.\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Failed to create directory: " << e.what() << std::endl;
        }
    }

    void removeFile(const std::string& name) {
        if (name.empty()) {
            std::cerr << "Error: File name cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(name, true)) {
            std::cerr << "Permission denied: Cannot remove file in this location.\n";
            return;
        }

        fs::path filePath = currentPath / name;
        try {
            if (currentDir->files.find(name) != currentDir->files.end() && fs::remove(filePath)) {
                currentDir->files.erase(name);
                std::cout << "File '" << name << "' deleted.\n";
            }
            else {
                std::cerr << "Failed to delete file: File not found.\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Failed to delete file: " << e.what() << std::endl;
        }
    }

    void removeDirectory(const std::string& name) {
        if (name.empty()) {
            std::cerr << "Error: Directory name cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(name, true)) {
            std::cerr << "Permission denied: Cannot remove directory in this location.\n";
            return;
        }

        fs::path dirPath = currentPath / name;
        try {
            if (currentDir->subdirectories.find(name) != currentDir->subdirectories.end() && fs::remove_all(dirPath)) {
                currentDir->subdirectories.erase(name);
                std::cout << "Directory '" << name << "' deleted.\n";
            }
            else {
                std::cerr << "Failed to delete directory: Directory not found or not empty.\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Failed to delete directory: " << e.what() << std::endl;
        }
    }

    void editFile(const std::string& name) {
        if (name.empty()) {
            std::cerr << "Error: File name cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(name, true)) {
            std::cerr << "Permission denied: Cannot edit file in this location.\n";
            return;
        }

        if (currentDir->files.find(name) == currentDir->files.end()) {
            // File doesn't exist in memory, try to load from disk
            fs::path filePath = currentPath / name;
            if (!fs::exists(filePath)) {
                std::cout << "File '" << name << "' doesn't exist. Creating a new file.\n";
                createFile(name);
            }
            else {
                // Load the file into memory
                std::ifstream file(filePath, std::ios::binary);
                if (file) {
                    std::stringstream buffer;
                    buffer << file.rdbuf();

                    File newFile;
                    newFile.name = name;
                    newFile.content = buffer.str();
                    newFile.owner = currentUser ? currentUser->username : "guest";
                    newFile.creationTime = std::time(nullptr);
                    newFile.modificationTime = std::time(nullptr);

                    currentDir->files[name] = newFile;
                }
            }
        }

        std::string content = currentDir->files[name].content;

        // Initialize lines
        std::vector<std::string> lines;
        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) {
            lines.push_back(line);
        }
        if (lines.empty()) lines.push_back(""); // Ensure at least one line

        // Initialize cursor position
        int cursorX = 0;
        int cursorY = 0;

        // Enable raw input mode
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hStdin == INVALID_HANDLE_VALUE || hStdout == INVALID_HANDLE_VALUE) {
            std::cerr << "Error getting console handle.\n";
            return;
        }

        DWORD originalConsoleMode;
        GetConsoleMode(hStdin, &originalConsoleMode);
        SetConsoleMode(hStdin, ENABLE_PROCESSED_INPUT); // This allows arrow keys to work properly

        bool editing = true;
        while (editing) {
            // Clear screen and display content
            system("cls");
            std::cout << "Editing file: " << name << "\n";
            std::cout << "Press Ctrl + X to save and exit.\n";

            // Display line numbers and content
            for (size_t i = 0; i < lines.size(); ++i) {
                printf("%3zu | ", i + 1); // Line number
                if (i == cursorY) {
                    std::cout << lines[i].substr(0, cursorX);
                    std::cout << "\033[7m \033[0m"; // Highlighted cursor
                    std::cout << (cursorX < lines[i].size() ? lines[i].substr(cursorX) : "") << "\n";
                }
                else {
                    std::cout << lines[i] << "\n";
                }
            }

            // Display status line
            std::cout << "\nLine: " << (cursorY + 1) << " Col: " << (cursorX + 1)
                << " | Total Lines: " << lines.size() << "\n";

            // Process input
            int ch = _getch();

            if (ch == 224 || ch == 0) { // Extended keys
                ch = _getch();
                switch (ch) {
                case 72: // Up arrow
                    if (cursorY > 0) {
                        cursorY--;
                        cursorX = (std::min)(cursorX, static_cast<int>(lines[cursorY].size()));
                    }
                    break;
                case 80: // Down arrow
                    if (cursorY < static_cast<int>(lines.size()) - 1) {
                        cursorY++;
                        cursorX = (std::min)(cursorX, static_cast<int>(lines[cursorY].size()));
                    }
                    break;
                case 75: // Left arrow
                    if (cursorX > 0) {
                        cursorX--;
                    }
                    else if (cursorY > 0) {
                        // Move to end of previous line
                        cursorY--;
                        cursorX = static_cast<int>(lines[cursorY].size());
                    }
                    break;
                case 77: // Right arrow
                    if (cursorX < static_cast<int>(lines[cursorY].size())) {
                        cursorX++;
                    }
                    else if (cursorY < static_cast<int>(lines.size()) - 1) {
                        // Move to beginning of next line
                        cursorY++;
                        cursorX = 0;
                    }
                    break;
                case 71: // Home
                    cursorX = 0;
                    break;
                case 79: // End
                    cursorX = static_cast<int>(lines[cursorY].size());
                    break;
                case 83: // Delete
                    if (cursorX < static_cast<int>(lines[cursorY].size())) {
                        lines[cursorY].erase(cursorX, 1);
                    }
                    else if (cursorY < static_cast<int>(lines.size()) - 1) {
                        // Join with next line
                        lines[cursorY] += lines[cursorY + 1];
                        lines.erase(lines.begin() + cursorY + 1);
                    }
                    break;
                }
            }
            else {
                switch (ch) {
                case 24: // Ctrl + X (Save and Exit)
                    editing = false;
                    break;
                case 8: // Backspace
                    if (cursorX > 0) {
                        lines[cursorY].erase(cursorX - 1, 1);
                        cursorX--;
                    }
                    else if (cursorY > 0) {
                        // Join with previous line
                        cursorX = static_cast<int>(lines[cursorY - 1].size());
                        lines[cursorY - 1] += lines[cursorY];
                        lines.erase(lines.begin() + cursorY);
                        cursorY--;
                    }
                    break;
                case 13: // Enter
                    lines.insert(lines.begin() + cursorY + 1, lines[cursorY].substr(cursorX));
                    lines[cursorY] = lines[cursorY].substr(0, cursorX);
                    cursorY++;
                    cursorX = 0;
                    break;
                case 9: // Tab - insert 4 spaces
                    lines[cursorY].insert(cursorX, 4, ' ');
                    cursorX += 4;
                    break;
                case 27: // Escape - does nothing but prevents beep
                    break;
                default: // Insert character (only printable characters)
                    if (ch >= 32 && ch <= 126) {
                        lines[cursorY].insert(cursorX, 1, static_cast<char>(ch));
                        cursorX++;
                    }
                    break;
                }
            }
        }

        // Restore console mode
        SetConsoleMode(hStdin, originalConsoleMode);

        // Save the edited content
        std::string newContent;
        for (size_t i = 0; i < lines.size(); ++i) {
            newContent += lines[i];
            if (i < lines.size() - 1) newContent += "\n";
        }

        // Update in memory and on disk
        currentDir->files[name].content = newContent;
        currentDir->files[name].modificationTime = std::time(nullptr);

        fs::path filePath = currentPath / name;
        try {
            std::ofstream file(filePath, std::ios::binary);
            if (file) {
                file << newContent;
                std::cout << "File '" << name << "' saved.\n";
            }
            else {
                std::cerr << "Failed to save file: Could not open file for writing.\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Failed to save file: " << e.what() << std::endl;
        }
    }
    void listFiles() {
        std::cout << "Contents of " << currentPath.string() << ":\n";

        // Count items
        size_t dirCount = currentDir->subdirectories.size();
        size_t fileCount = currentDir->files.size();

        if (dirCount == 0 && fileCount == 0) {
            std::cout << "  (empty directory)\n";
            return;
        }

        // Get and sort directory names
        std::vector<std::string> dirNames;
        for (const auto& [name, _] : currentDir->subdirectories) {
            dirNames.push_back(name);
        }
        std::sort(dirNames.begin(), dirNames.end());

        // Get and sort file names
        std::vector<std::string> fileNames;
        for (const auto& [name, _] : currentDir->files) {
            fileNames.push_back(name);
        }
        std::sort(fileNames.begin(), fileNames.end());

        // Display directories
        for (const auto& name : dirNames) {
            std::cout << "\033[1;34m" << name << "/\033[0m\n"; // Blue for directories
        }

        // Display files
        for (const auto& name : fileNames) {
            std::cout << "\033[1;32m" << name << "\033[0m\n"; // Green for files
        }

        std::cout << "\n" << dirCount << " directories, " << fileCount << " files\n";
    }

    void changeDirectory(const std::string& name) {
        if (name.empty()) {
            std::cerr << "Error: Directory name cannot be empty.\n";
            return;
        }

        if (name == ".." && pathStack.size() > 1) {
            pathStack.pop_back();
            currentDir = pathStack.back();
            currentPath = currentPath.parent_path();
            std::cout << "Changed to parent directory: " << currentPath.string() << "\n";
        }
        else if (name == ".") {
            // Stay in the current directory
            std::cout << "Current directory: " << currentPath.string() << "\n";
        }
        else if (currentDir->subdirectories.find(name) != currentDir->subdirectories.end()) {
            currentDir = &currentDir->subdirectories[name];
            pathStack.push_back(currentDir);
            currentPath /= name;
            std::cout << "Changed to directory: " << currentPath.string() << "\n";
        }
        else {
            std::cout << "Directory '" << name << "' not found.\n";
        }
    }

    void displayHelp() {
        std::cout << "\n====================== VFS HELP ======================\n";
        std::cout << "Available commands:\n";
        std::cout << "  ls                - List files and directories\n";
        std::cout << "  mkdir <name>      - Create a new directory\n";
        std::cout << "  rmdir <name>      - Remove a directory\n";
        std::cout << "  touch <name>      - Create a new empty file\n";
        std::cout << "  rm <name>         - Remove a file\n";
        std::cout << "  edit <name>       - Edit a file with the built-in editor\n";
        std::cout << "  cat <name>        - Display the content of a file\n";
        std::cout << "  cd <name>         - Change directory\n";
        std::cout << "  cd ..             - Move to the parent directory\n";
        std::cout << "  pwd               - Show current directory path\n";
        std::cout << "  rename <old> <new>- Rename a file or directory\n";
        std::cout << "  copy <src> <dest> - Copy a file or directory\n";
        std::cout << "  mount <path>      - Change the mounted directory\n";
        std::cout << "  clear             - Clear the terminal screen\n";
        std::cout << "  help              - Display this help message\n";
        std::cout << "  exit              - Exit the VFS\n";
        std::cout << "\n=== Editor Shortcuts ===\n";
        std::cout << "  Arrow keys        - Move cursor\n";
        std::cout << "  Home/End          - Move to start/end of line\n";
        std::cout << "  Enter             - Insert new line\n";
        std::cout << "  Backspace         - Delete character to the left\n";
        std::cout << "  Delete            - Delete character under cursor\n";
        std::cout << "  Tab               - Insert 4 spaces\n";
        std::cout << "  Ctrl+X            - Save and exit\n";
        std::cout << "======================================================\n";
    }

    void displayFileContent(const std::string& name) {
        if (name.empty()) {
            std::cerr << "Error: File name cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(name)) {
            std::cerr << "Permission denied: Cannot access file in this location.\n";
            return;
        }

        if (currentDir->files.find(name) != currentDir->files.end()) {
            std::cout << "Content of file '" << name << "':\n";
            std::cout << "--------------------------------------\n";
            std::cout << currentDir->files[name].content << "\n";
            std::cout << "--------------------------------------\n";
        }
        else {
            std::cout << "File '" << name << "' not found.\n";
        }
    }

    void renameFileOrDirectory(const std::string& oldName, const std::string& newName) {
        if (oldName.empty() || newName.empty()) {
            std::cerr << "Error: File/directory names cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(oldName, true)) {
            std::cerr << "Permission denied: Cannot rename file/directory in this location.\n";
            return;
        }

        fs::path oldPath = currentPath / oldName;
        fs::path newPath = currentPath / newName;

        // Check if destination already exists
        if (fs::exists(newPath)) {
            std::cerr << "Cannot rename: destination already exists.\n";
            return;
        }

        try {
            fs::rename(oldPath, newPath);
            bool renamed = false;

            // Handle file renaming
            if (currentDir->files.find(oldName) != currentDir->files.end()) {
                currentDir->files[newName] = currentDir->files[oldName];
                currentDir->files[newName].name = newName;
                currentDir->files.erase(oldName);
                std::cout << "File renamed from '" << oldName << "' to '" << newName << "'.\n";
                renamed = true;
            }

            // Handle directory renaming
            if (currentDir->subdirectories.find(oldName) != currentDir->subdirectories.end()) {
                currentDir->subdirectories[newName] = currentDir->subdirectories[oldName];
                currentDir->subdirectories.erase(oldName);
                std::cout << "Directory renamed from '" << oldName << "' to '" << newName << "'.\n";
                renamed = true;
            }

            if (!renamed) {
                std::cout << "File or directory not found in VFS (but rename on disk succeeded).\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Failed to rename: " << e.what() << std::endl;
        }
    }

    void copyFileOrDirectory(const std::string& src, const std::string& dest) {
        if (src.empty() || dest.empty()) {
            std::cerr << "Error: Source and destination names cannot be empty.\n";
            return;
        }

        // Check permissions
        if (!checkPermission(src)) {
            std::cerr << "Permission denied: Cannot access source file/directory.\n";
            return;
        }

        if (!checkPermission(dest, true)) {
            std::cerr << "Permission denied: Cannot write to destination.\n";
            return;
        }

        // Source path is always relative to current directory
        fs::path srcPath = currentPath / src;

        // Check if destination contains a path separator
        fs::path destPath;
        if (dest.find('/') != std::string::npos || dest.find('\\') != std::string::npos) {
            // If dest contains path separators, treat it as a full path
            if (fs::path(dest).is_absolute()) {
                destPath = dest;
            }
            else {
                // Relative path from vfsRoot
                destPath = vfsRoot / dest;
            }
        }
        else {
            // No path separators, assume it's just a filename in current directory
            destPath = currentPath / dest;
        }

        // Check if source exists
        if (!fs::exists(srcPath)) {
            std::cerr << "Source '" << src << "' not found.\n";
            return;
        }

        try {
            // Ensure the destination directory exists
            fs::create_directories(destPath.parent_path());

            if (fs::is_directory(srcPath)) {
                // Copy directory recursively, creating the destination if it doesn't exist
                if (!fs::exists(destPath)) {
                    fs::create_directories(destPath);
                }

                // Copy directory contents
                for (const auto& entry : fs::recursive_directory_iterator(srcPath)) {
                    fs::path relPath = fs::relative(entry.path(), srcPath);
                    fs::path targetPath = destPath / relPath;

                    if (entry.is_directory()) {
                        fs::create_directories(targetPath);
                    }
                    else {
                        fs::copy_file(entry.path(), targetPath, fs::copy_options::overwrite_existing);
                    }
                }

                std::cout << "Directory copied from '" << srcPath.string() << "' to '" << destPath.string() << "'.\n";

                // Update the VFS structure - reload the directory
                loadVFS(vfsRoot, root);
                // Navigate back to where we were
                Directory* tempDir = &root;
                std::deque<Directory*> newPathStack{ tempDir };
                for (const auto& part : fs::relative(currentPath, vfsRoot)) {
                    if (tempDir->subdirectories.find(part.string()) != tempDir->subdirectories.end()) {
                        tempDir = &tempDir->subdirectories[part.string()];
                        newPathStack.push_back(tempDir);
                    }
                }
                pathStack = newPathStack;
                currentDir = pathStack.back();
            }
            else if (fs::is_regular_file(srcPath)) {
                // If destination is a directory, add the source filename
                if (fs::exists(destPath) && fs::is_directory(destPath)) {
                    destPath = destPath / srcPath.filename();
                }

                fs::copy_file(srcPath, destPath, fs::copy_options::overwrite_existing);

                std::cout << "File copied from '" << srcPath.string() << "' to '" << destPath.string() << "'.\n";

                // Update the VFS structure by reloading
                loadVFS(vfsRoot, root);
                // Navigate back to where we were
                Directory* tempDir = &root;
                std::deque<Directory*> newPathStack{ tempDir };
                for (const auto& part : fs::relative(currentPath, vfsRoot)) {
                    if (tempDir->subdirectories.find(part.string()) != tempDir->subdirectories.end()) {
                        tempDir = &tempDir->subdirectories[part.string()];
                        newPathStack.push_back(tempDir);
                    }
                }
                pathStack = newPathStack;
                currentDir = pathStack.back();
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Failed to copy: " << e.what() << std::endl;
        }
    }

    void clearScreen() {
        system("cls");
    }

    void showCurrentPath() {
        std::cout << "Current directory: " << currentPath.string() << "\n";
    }

    void changeMount(const std::string& newPath) {
        // Validate the new path
        fs::path path = newPath;
        if (path.empty()) {
            std::cerr << "Error: Path cannot be empty.\n";
            return;
        }

        try {
            // Check if the path exists, if not try to create it
            if (!fs::exists(path)) {
                std::cout << "Directory does not exist. Create it? (y/n): ";
                char choice;
                std::cin >> choice;
                std::cin.ignore(); // Clear the newline character

                if (choice == 'y' || choice == 'Y') {
                    fs::create_directories(path);
                    std::cout << "Directory created successfully.\n";
                }
                else {
                    std::cout << "Mount operation canceled.\n";
                    return;
                }
            }

            // Validate that it's a directory
            if (fs::is_directory(path)) {
                vfsRoot = path;

                // Save the new configuration
                saveConfiguration();

                // Reset the VFS and reload from the new location
                root = Directory();
                loadVFS(vfsRoot, root);

                // Reset navigation
                currentDir = &root;
                pathStack.clear();
                pathStack.push_back(currentDir);
                currentPath = vfsRoot;

                std::cout << "Directory mounted successfully: " << vfsRoot << std::endl;
            }
            else {
                std::cerr << "Error: The specified path is not a directory.\n";
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

    void showMountInfo() {
        std::cout << "Current VFS root: " << vfsRoot.string() << std::endl;
        std::cout << "Configuration file: " << CONFIG_FILE_PATH.string() << std::endl;
    }
};

int main() {
    // Set console title
    SetConsoleTitle(TEXT("C++ Virtual File System"));

    // Enable console color
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode;
    GetConsoleMode(hConsole, &consoleMode);
    SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Initialize VFS
    VFS vfs;

    // Authenticate user
    while (!vfs.isAuthenticated) {
        if (!vfs.authenticate()) {
            continue; // Retry authentication if failed
        }
    }

    // Welcome message
    std::cout << "\033[1;36m========================================================\033[0m\n";
    std::cout << "\033[1;33m             C++ VIRTUAL FILE SYSTEM by tj\033[0m\n";
    std::cout << "\033[1;36m========================================================\033[0m\n";
    std::cout << "Type 'help' for a list of commands.\n\n";

    std::string command;

    while (true) {
        std::cout << "\033[1;32m" << vfs.currentPath.string() << "\033[0m > ";
        std::getline(std::cin, command);

        if (command.empty()) {
            continue;
        }

        // Split command into words
        std::vector<std::string> args;
        std::istringstream iss(command);
        std::string arg;
        while (iss >> arg) {
            args.push_back(arg);
        }

        if (args.empty()) continue;

        std::string cmd = args[0];

        if (cmd == "exit" || cmd == "quit") {
            std::cout << "Exiting VFS...\n";
            break;
        }

        if (cmd == "ls") {
            vfs.listFiles();
        }
        else if (cmd == "mkdir" && args.size() > 1) {
            vfs.createDirectory(args[1]);
        }
        else if (cmd == "rmdir" && args.size() > 1) {
            vfs.removeDirectory(args[1]);
        }
        else if (cmd == "touch" && args.size() > 1) {
            vfs.createFile(args[1]);
        }
        else if (cmd == "rm" && args.size() > 1) {
            vfs.removeFile(args[1]);
        }
        else if (cmd == "edit" && args.size() > 1) {
            vfs.editFile(args[1]);
        }
        else if (cmd == "cd" && args.size() > 1) {
            vfs.changeDirectory(args[1]);
        }
        else if (cmd == "cat" && args.size() > 1) {
            vfs.displayFileContent(args[1]);
        }
        else if (cmd == "rename" && args.size() > 2) {
            vfs.renameFileOrDirectory(args[1], args[2]);
        }
        else if (cmd == "copy" && args.size() > 2) {
            vfs.copyFileOrDirectory(args[1], args[2]);
        }
        else if (cmd == "clear") {
            vfs.clearScreen();
        }
        else if (cmd == "help") {
            vfs.displayHelp();
        }
        else if (cmd == "pwd") {
            vfs.showCurrentPath();
        }
        else if (cmd == "mount") {
            if (args.size() > 1) {
                vfs.changeMount(args[1]);
            }
            else {
                // Show current mount info if no path is specified
                vfs.showMountInfo();
                std::cout << "Usage: mount <path> - to change the mounted directory\n";
            }
        }
        else if (cmd == "passwd" && args.size() > 1) {
            vfs.changePassword(args[1]);
        }
        else if (cmd == "adduser" && args.size() > 1) {
            vfs.createUser(args[1]);
        }
        else {
            std::cout << "Unknown command: " << cmd << "\n";
            std::cout << "Type 'help' for a list of available commands.\n";
        }
    }

    return 0;
}