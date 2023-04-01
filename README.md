# smtp-log-auditor 

version: 1.0

Author: Mohamed Ali (https://twitter.com/MohamedNab1l)

smtp-log-auditor will detect potential brute-force login attacks against all SMTP user's emails. If the number of failed login attempts from a given IP address exceeds a certain threshold, the script alerts the user and outputs the IP address, username, date, number of failed attempts, and location information to a CSV file.

  

## To run this script, you will need the following:

Python 3.6 or later installed on your system.
The geoip2 Python package installed. You can install it using pip by running pip install geoip2.
A MaxMind GeoIP2 database file.


You may need to set the login_threshold, geoip2_database, and smtp_failed_login_attempts variables in the script to suit your needs.

  
