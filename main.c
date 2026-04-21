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

typedef struct {
    char field[30];
    char op[5];
    char value[50];
} Condition;

/**
 * AI-Generated function to split the condition string "field:operator:value"
 */
int parse_condition(const char *input, Condition *cond) {
    if (sscanf(input, "%29[^:]:%4[^:]:%49s", cond->field, cond->op, cond->value) == 3) {
        return 1;
    }
    return 0;
}

/**
 * AI-Generated function to check if a report matches the parsed condition
 */
int match_condition(Report r, Condition cond) {
    if (strcmp(cond.field, "severity") == 0) {
        int val = atoi(cond.value);
        if (strcmp(cond.op, "=") == 0) return r.severity == val;
        if (strcmp(cond.op, ">") == 0) return r.severity > val;
        if (strcmp(cond.op, "<") == 0) return r.severity < val;
        if (strcmp(cond.op, ">=") == 0) return r.severity >= val;
        if (strcmp(cond.op, "<=") == 0) return r.severity <= val;
    } else if (strcmp(cond.field, "category") == 0) {
        if (strcmp(cond.op, "=") == 0) return strcmp(r.category, cond.value) == 0;
    } else if (strcmp(cond.field, "id") == 0) {
        int val = atoi(cond.value);
        if (strcmp(cond.op, "=") == 0) return r.id == val;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    char *role = NULL, *user = NULL, *district = NULL, *cmd = NULL;
    char *target_id_str = NULL; // To store the report ID from command line
    char *threshold_val = NULL; // To store the new threshold value
    char *condition_str = NULL;


// 1.Argument Parsing [cite: 12, 13]
    // 1. Corrected Argument Parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) role = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) user = argv[++i];
        else if (strcmp(argv[i], "--add") == 0 && i + 1 < argc) { cmd = "add"; district = argv[++i]; }
        else if (strcmp(argv[i], "--list") == 0 && i + 1 < argc) { cmd = "list"; district = argv[++i]; }
        else if (strcmp(argv[i], "--view") == 0 && i + 2 < argc) { 
            cmd = "view"; 
            district = argv[++i]; 
            target_id_str = argv[++i]; 
        }
        else if (strcmp(argv[i], "--remove_report") == 0 && i + 2 < argc) {
            cmd = "remove_report";
            district = argv[++i];
            target_id_str = argv[++i];
        }
        else if (strcmp(argv[i], "--update_threshold") == 0 && i + 2 < argc) {
            cmd = "update_threshold";
            district = argv[++i];
            threshold_val = argv[++i];
        }
        else if (strcmp(argv[i], "--filter") == 0 && i + 2 < argc) {
            cmd = "filter";
            district = argv[++i];
            condition_str = argv[++i];
        }
    }
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

        char config_path[256];
        sprintf(config_path, "%s/district.cfg", district);
        int cfg_fd = open(config_path, O_CREAT | O_WRONLY | O_EXCL, 0640);
        if (cfg_fd != -1) {
            write(cfg_fd, "2", 1); // Set a default threshold of 2
            close(cfg_fd);
        }
        // Ensure permissions are set even if file existed [cite: 32]
        chmod(config_path, 0640);
        
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
    if (cmd != NULL && strcmp(cmd, "remove_report") == 0) {
        // 1. Role-based access control: Manager only [cite: 14, 44]
        if (strcmp(role, "manager") != 0) {
            printf("Error: Only the manager role may remove reports.\n");
            return 1;
        }

        int fd = open(repo_path, O_RDWR); // Open for reading and writing [cite: 80]
        if (fd == -1) { perror("Error opening reports file"); return 1; }

        int target_id = atoi(target_id_str);
        Report r;
        off_t current_pos;
        int found = 0;

        // 2. Search for the report to remove [cite: 72]
        while (read(fd, &r, sizeof(Report)) > 0) {
            if (r.id == target_id) {
                // Get the starting position of the record to delete 
                current_pos = lseek(fd, 0, SEEK_CUR) - sizeof(Report);
                found = 1;
                break;
            }
        }

        if (found) {
            // 3. Shifting subsequent records 
            Report next_r;
            while (read(fd, &next_r, sizeof(Report)) > 0) {
                off_t read_pos = lseek(fd, 0, SEEK_CUR); // Remember where we are
                lseek(fd, current_pos, SEEK_SET);      // Move back to overwrite [cite: 80]
                write(fd, &next_r, sizeof(Report));
                current_pos = lseek(fd, 0, SEEK_CUR);  // Update position for next overwrite
                lseek(fd, read_pos, SEEK_SET);         // Return to continue reading
            }

            // 4. Truncate the file to final size 
            struct stat st;
            fstat(fd, &st);
            ftruncate(fd, st.st_size - sizeof(Report)); 
            
            printf("Report %d removed successfully from district %s.\n", target_id, district);
            log_operation(log_path, role, user, "Removed report");
        } else {
            printf("Report %d not found.\n", target_id);
        }
        close(fd);
    }

    if (cmd != NULL && strcmp(cmd, "update_threshold") == 0) {
        char config_path[256];
        sprintf(config_path, "%s/district.cfg", district);

        // 1. Security Check: Only manager role can write to district.cfg [cite: 31, 46]
        if (strcmp(role, "manager") != 0) {
            printf("Access Denied: Only managers can update thresholds.\n");
            return 1;
        }

        // 2. Extra Requirement: Call stat() and verify permissions match 640 before writing [cite: 47, 48]
        struct stat st;
        if (stat(config_path, &st) == 0) {
            // Check if permissions are exactly 640 (rw-r-----)
            if ((st.st_mode & 0777) != 0640) {
                printf("Diagnostic: Permissions on %s are not 640! Refusing to write.\n", config_path);
                return 1;
            }
        }

        // 3. Write the new threshold value
        int cfg_fd = open(config_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (cfg_fd != -1) {
            write(cfg_fd, threshold_val, strlen(threshold_val));
            close(cfg_fd);
            printf("Severity threshold updated to %s for district %s.\n", threshold_val, district);
            log_operation(log_path, role, user, "Updated severity threshold"); // [cite: 26]
        } else {
            perror("Error opening config file");
        }
    }
    if (cmd != NULL && strcmp(cmd, "filter") == 0) {
        // 1. Security Check: Read access needed
        if (!check_permission(repo_path, role, 0)) {
            printf("Access Denied for role %s\n", role);
            return 1;
        }

        Condition cond;
        if (!parse_condition(condition_str, &cond)) {
            printf("Invalid condition format. Use field:op:value\n");
            return 1;
        }

        int fd = open(repo_path, O_RDONLY);
        if (fd == -1) { perror("Error"); return 1; }

        Report r;
        int found_any = 0;
        printf("--- Filtered Results (%s) ---\n", condition_str);
        
        while (read(fd, &r, sizeof(Report)) > 0) {
            if (match_condition(r, cond)) {
                printf("ID: %d | Cat: %s | Sev: %d | Desc: %s\n", 
                       r.id, r.category, r.severity, r.description);
                found_any = 1;
            }
        }

        if (!found_any) printf("No reports matched the criteria.\n");

        close(fd);
        log_operation(log_path, role, user, "Filtered reports");
    }
    return 0;
}