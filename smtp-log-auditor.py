""""
smtp-log-auditor version: 1.0
Author: Mohamed Ali (https://twitter.com/MohamedNab1l)

This script will detect potential brute-force login attacks against all SMTP user's emails. If the number of failed login attempts from a given IP address exceeds a certain threshold, the script alerts the user and outputs the IP address, username, date, number of failed attempts, and location information to a CSV file.

To run this script, you will need the following:
Python 3.6 or later installed on your system.
The geoip2 Python package installed. You can install it using pip by running pip install geoip2.
A MaxMind GeoIP2 database file. You can download a free GeoLite2 database from the MaxMind website at https://dev.maxmind.com/geoip/geoip2/geolite2/.

You may need to set the login_threshold, geoip2_database, and smtp_failed_login_attempts variables in the script to suit your needs.

Feel free to contact me if you do have any questions or suggestions.
"""
import re
import io
import csv
from datetime import datetime

# Set the path to the SMTP log file
smtp_log_file = '/var/log/mail.log'

# Set the threshold for failed login attempts
login_threshold = 10

# Set the path to the MaxMind GeoIP2 database
geoip2_database = 'geolite-db/GeoLite2-City.mmdb'

# Set the path to the CSV output file
csv_output_file = 'smtp_failed_login_attempts.csv'

try:
    # Read the SMTP log file
    with io.open(smtp_log_file, 'r', encoding='utf-8') as f:
        log_data = f.read()
except FileNotFoundError:
    print("Error: {} not found.".format(smtp_log_file))
    exit(1)

# Use regular expressions to find failed login attempts and extract the IP addresses, dates, and usernames
log_pattern = re.compile('.*smtpd.*authentication failure.*rhost=(\S+).*user=([^ ]+).*')
log_matches = log_pattern.findall(log_data)

# Create a dictionary to store the failed login attempts
# The keys are tuples of (IP address, username, date)
# The values are the number of failed login attempts for that combination
failed_logins = {}

# Loop through the log matches and update the failed_logins dictionary
for match in log_matches:
    ip_address = match[0]
    username = match[1]
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    key = (ip_address, username, date)
    if key in failed_logins:
        failed_logins[key] += 1
    else:
        failed_logins[key] = 1

# Filter the failed login attempts based on the threshold
filtered_logins = [key for key, count in failed_logins.items() if count > login_threshold]

# If any failed login attempts meet the threshold, alert the user and display the location of each IP address
if filtered_logins:
    print('Potential brute-force login attacks detected from the following IP addresses:')
    with geoip2.database.Reader(geoip2_database) as reader, open(csv_output_file, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['IP Address', 'Username', 'Date', 'Failed Login Attempts', 'City', 'State/Province', 'Country'])
        for key in filtered_logins:
            ip_address, username, date = key
            count = failed_logins[key]
            response = reader.city(ip_address)
            row = [ip_address, username, date, count, response.city.name, response.subdivisions.most_specific.name, response.country.name]
            writer.writerow(row)
            print('{}: {} failed login attempts detected for user {} on {}. Location: {}, {}, {}'.format(
                ip_address, count, username, date, response.city.name, response.subdivisions.most_specific.name, response.country.name))
else:
    print('No potential brute-force login attacks detected.')

