#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

// [cite: 17-24]
typedef struct {
    int id;
    char inspector[50];
    float latitude;
    float longitude;
    char category[30];
    int severity;
    time_t timestamp;
    char description[256];
} Report;

// Helper to check permissions before actions [cite: 33, 92]
int check_permission(const char *path, const char *role, int want_write) {
    struct stat st;
    if (stat(path, &st) == -1) return 1; // If file doesn't exist, assume we can create it

    if (strcmp(role, "manager") == 0) {
        return (want_write) ? (st.st_mode & S_IWUSR) : (st.st_mode & S_IRUSR);
    } else {
        return (want_write) ? (st.st_mode & S_IWGRP) : (st.st_mode & S_IRGRP);
    }
}

// Function to convert bits to string (REQUIRED) [cite: 37, 94]
void mode_to_string(mode_t mode, char *str) {
    strcpy(str, "---------");
    if (mode & S_IRUSR) str[0] = 'r';
    if (mode & S_IWUSR) str[1] = 'w';
    if (mode & S_IXUSR) str[2] = 'x';
    if (mode & S_IRGRP) str[3] = 'r';
    if (mode & S_IWGRP) str[4] = 'w';
    if (mode & S_IXGRP) str[5] = 'x';
    if (mode & S_IROTH) str[6] = 'r';
    if (mode & S_IWOTH) str[7] = 'w';
    if (mode & S_IXOTH) str[8] = 'x';
}

// Helper function to log every operation 
void log_operation(const char *log_path, const char *role, const char *user, const char *action) {
    int fd = open(log_path, O_CREAT | O_WRONLY | O_APPEND, 0644); // Anyone reads, Manager writes [cite: 31]
    if (fd != -1) {
        time_t now = time(NULL);
        char *ts = ctime(&now);
        ts[strlen(ts) - 1] = '\0'; // Remove newline

        char buffer[512];
        int len = sprintf(buffer, "[%s] Role: %s, User: %s, Action: %s\n", ts, role, user, action);
        write(fd, buffer, len);
        close(fd);
    }
}

int main(int argc, char *argv[]) {
    char *role = NULL, *user = NULL, *district = NULL, *cmd = NULL;
    char *target_id_str = NULL; // To store the report ID from command line

// 1.Argument Parsing [cite: 12, 13]
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0) role = argv[++i];
        else if (strcmp(argv[i], "--user") == 0) user = argv[++i];
        else if (strcmp(argv[i], "--add") == 0) { cmd = "add"; district = argv[++i]; }
        else if (strcmp(argv[i], "--list") == 0) { cmd = "list"; district = argv[++i]; }
        // The view command takes two extra arguments: district and ID 
        else if (strcmp(argv[i], "--view") == 0 && i + 2 < argc) { 
            cmd = "view"; 
            district = argv[++i]; 
            target_id_str = argv[++i]; 
        }
    }

    if (!role || !user || !district) return 1;

// 2. P// 2. Paths and Symlink Names
    char repo_path[256], link_name[256], log_path[256];
    sprintf(repo_path, "%s/reports.dat", district);
    sprintf(link_name, "active_reports-%s", district);
    sprintf(log_path, "%s/logged_district", district);

    // Symbolic Link Validation [cite: 77, 78] ---
    struct stat link_stat;
    if (lstat(link_name, &link_stat) == 0) {
        if (S_ISLNK(link_stat.st_mode)) {
            struct stat target_stat;
            if (stat(link_name, &target_stat) == -1) {
                printf("Warning: Symbolic link %s is dangling (points to nothing)!\n", link_name);
            }
        }
    }

// 3. Command Execution Logic

    if (strcmp(cmd, "add") == 0) {
        // Create directory first [cite: 16, 32]
        mkdir(district, 0750);
        chmod(district, 0750);

        // Security check before opening 
        if (!check_permission(repo_path, role, 1)) {
            printf("Access Denied for role %s\n", role);
            return 1;
        }

        int fd = open(repo_path, O_CREAT | O_WRONLY | O_APPEND, 0664);
        chmod(repo_path, 0664); // [cite: 41]

        // Create the symbolic link [cite: 76, 80]
        symlink(repo_path, link_name);

        // Fill and write the binary report [cite: 39, 72]
        Report r = { .id = 1, .severity = 2, .timestamp = time(NULL) };
        strncpy(r.inspector, user, 50);
        write(fd, &r, sizeof(Report));
        close(fd);
        
        printf("Report added successfully.\n");
    }

    if (strcmp(cmd, "list") == 0) {
        struct stat st;
        // Check if we can read the reports file [cite: 33]
        if (stat(repo_path, &st) == -1) {
            perror("Error: District does not exist or reports.dat is missing");
            return 1;
        }

        // Show file metadata as required [cite: 36]
        char perm_str[11];
        mode_to_string(st.st_mode, perm_str);
        printf("File: %s | Permissions: %s | Size: %ld bytes | Last Mod: %s",
               repo_path, perm_str, st.st_size, ctime(&st.st_mtime));

        // Open and read binary records [cite: 42, 72]
        int fd = open(repo_path, O_RDONLY);
        if (fd != -1) {
            Report r;
            printf("\nID  | Inspector  | Category   | Sev | Description\n");
            printf("--------------------------------------------------\n");
            while (read(fd, &r, sizeof(Report)) > 0) {
                printf("%-3d | %-10s | %-10s | %d   | %s\n", 
                       r.id, r.inspector, r.category, r.severity, r.description);
            }
            close(fd);
        }
        
        log_operation(log_path, role, user, "Listed reports"); // 
    }

    if (cmd != NULL && strcmp(cmd, "view") == 0) {
        // Security check: Both roles can read district.cfg and reports.dat [cite: 31, 43]
        if (!check_permission(repo_path, role, 0)) { // 0 means we only want to read
            printf("Access Denied: Your role (%s) cannot view reports.\n", role);
            return 1;
        }

        int fd = open(repo_path, O_RDONLY);
        if (fd == -1) {
            perror("Error opening reports file");
            return 1;
        }

        int target_id = atoi(target_id_str); // Convert string ID to integer
        Report r;
        int found = 0;

        // Read records one by one until we find the ID [cite: 72]
        while (read(fd, &r, sizeof(Report)) > 0) {
            if (r.id == target_id) {
                printf("\n--- Detailed Report Info ---\n");
                printf("ID:          %d\n", r.id);
                printf("Inspector:   %s\n", r.inspector);
                printf("Coordinates: %f, %f\n", r.latitude, r.longitude);
                printf("Category:    %s\n", r.category);
                printf("Severity:    %d\n", r.severity);
                printf("Timestamp:   %s", ctime(&r.timestamp));
                printf("Description: %s\n", r.description);
                printf("---------------------------\n");
                found = 1;
                break; // Stop searching once found
            }
        }

        if (!found) {
            printf("Report with ID %d not found in district %s.\n", target_id, district);
        }

        close(fd);
        log_operation(log_path, role, user, "Viewed report details"); // [cite: 26]
    }
    return 0;
}