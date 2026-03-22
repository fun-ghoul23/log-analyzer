# Log Analyzer - by fun_ghoul23
# This script reads a log file and flags suspicious activity

suspicious_keywords = ["FAILED", "WARNING", "Unauthorized"]
failed_login_threshold = 3

#keeps score
failed_logins = {}
#collects suspicious words in the log
warnings = []

#reads lines in the file and stores in list 'lines'
with open("sample_log.txt", "r") as log:
    lines = log.readlines()

#reads line by line
for line in lines:
    for keyword in suspicious_keywords:
        #checks for keywords
        if keyword in line:
            warnings.append(line.strip())
            #adds +1 to the 'score'
            if "FAILED" in line:
                user = line.split("User ")[1].split(" ")[0]
                failed_logins[user] = failed_logins.get(user, 0) + 1
            
# prints all suspicious lines found in the log
print("\n--- SUSPICIOUS ACTIVITY FOUND ---")
for warning in warnings:
    print(warning)

# checks who crossed the failed login threshold
print("\n--- USERS WITH TOO MANY FAILED LOGINS ---")
for user, count in failed_logins.items():
    if count >= failed_login_threshold:
        print(f"ALERT: {user} had {count} failed login attempts")