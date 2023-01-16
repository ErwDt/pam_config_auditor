import os

# Security recommendations
recommendations = {
    "/etc/pam.d/su": ["auth required pam_wheel.so use_uid root_only"],
    "/etc/pam.d/su-l": ["auth required pam_wheel.so use_uid root_only"],
    "/etc/pam.d/passwd": ["password required pam_pwquality.so minlen=12 minclass=3 dcredit=0 ucredit=0"],
    "/etc/pam.d/login": ["auth required pam_faillock.so deny=3 unlock_time=300"],
    "/etc/pam.d/sshd": ["auth required pam_faillock.so deny=3 unlock_time=300"],
    "/etc/pam.d/common-password": ["password required pam_unix.so obscure yescrypt rounds=11"]
}

non_compliant_settings = {}
compliant_settings = []
#check config files and compare to recommendations
for file_path in recommendations:
    if os.path.isfile(file_path):
        with open(file_path, "r") as f:
            file_lines = f.readlines()
            file_lines = [x.strip() for x in file_lines]
            compliant = True
            for recommended_line in recommendations[file_path]:
                if recommended_line not in file_lines:
                    non_compliant_settings[file_path] = recommended_line
                    compliant = False
            if compliant:
                compliant_settings.append(file_path)
    else:
        print(f"{file_path} does not exist.")

# Print results
if compliant_settings:
    print("The following files are compliant with security recommendations:")
    for file_path in compliant_settings:
        print(file_path)
if non_compliant_settings:
    print("The following files are NOT compliant with security recommendations, some parameters are missing:")
    for file_path, line in non_compliant_settings.items():
        print(f"{file_path}: {line}")
else:
    print("All files are compliant with security recommendations.")
