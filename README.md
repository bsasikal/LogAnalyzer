# Log file Analysis Application

This application is developed to address Insight Data Engineer Program Challenge (2017)
(https://github.com/InsightDataScience/fansite-analytics-challenge)


# Implementation Details

### Feature 1 - List the top 10 active host / IP addresses that have accessed the site in descending order.

Input File: log.txt
Output File: hosts.txt

Implementation Details:
1. For every line in input file, extract host name or IP address (first column of the input record).
2. Maintain a HashMap to track host and counter.
3. Check the HashMap to see if the host name/ IP address already exists.
4. If the record exists, increase the counter
5. If the record does not exist, create a new entry.
6. Continue 1-5 for rest of the records in the input file

### Feature 2 - Identify to 10 resources that consume the most bandwidth on the site in descending order

Input File: log.txt
Output File: resources.txt

Assumptions:
- Http request has 3 parts Request Type, Request URI, HTTP version, all separated by whitespace
- Request URL will have "/" and should not have any whitespace
- Any whitespace if found in the request URI will be ignored and the string with "/" tokens will only be considered as URI

Implementation Details:
1. For every line in input file, extract http request (5th column of the input record that is within quotes) and the no of bytes (7th column of the input record)
2. Extract only resource URI from http request.
3. Maintain a HashMap to track resource URI and bandwidth.
4. Check the HashMap to see if the resource URI already exists.
5. If it exists, then add current bytes to the existing bytes.
6. If not create a new entry with the current bytes.
7. Repeat steps 1-6 for rest of the records in input file.

### Feature 3 - List top 10 busiest (or most frequently visited) 60-minute periods

Assumptions:
- The clock starts with the time of the first event. Count all the events that happens in the next 60 min time interval.
- As soon as the time window (60 min) expires, reset the clock with the time of the next event in line and calculate the next 60 minute window
- Repeat the steps till end of file is reached
In other words, log the 60 minute usage (no of hits) from the time when the event is tracked at a non-overlapping time interval (like a tumbling window).

Input File: log.txt
Output File: hours.txt

Implementation Details:
1. For every line in input file, extract event time (4th column of the input record)
2. Track the event time (begin_event_time) in a global variable
3. Calculate the 60 minute window for the current event time (add 60 mins to current event time)
4) Maintain a HashMap to track the window details
5. Create a new entry in the Map with event time of the first record as key and counter as value initialized to 1.
6. Iterate next record and check if the event time of the record is within the the 60 minute window interval.
7. If yes, then increase the counter of the begin_event_time in the HashMap.
8. If no (i.e., the event_time of the current input record is past the 60 minute window), reset the begin_event_time to the event_time of the current record. Calculate 60 minute window based on current event time; Add a new entry to the HashMap with the event_time of the current record as key and counter as value initialized to 1.
9. Repeat step 6 to 8 till end of the input file.

### Feature 4 - Detect patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be blocked for 5 minutes.

Input File: log.txt
Output File: blocked.txt

Implementation Details:
1. For every line in input file, extract event time (4th column of the input record) and the host name/IP address (1st column of the input record)
2. Keep a HashMap to track the failed login attempts
3. If the HTTP response code is 401, then check if the map contains the host entry (login failure being tracked).
   3(a) If map does not contain the host, then create an entry and derive the 20 second tracking window to track the successive failed attempts.
   3(b) If map already contains host record, check for the max no of failed attempts
            If no of failed attempts is less than 3 and the event time is within tracking window, increment the failed attempt count
            if no of failed attempts is greater than 3 and the event time is within tracking window, increment the failed attempt count and log the record
            if no of failed attempts is greater than 3 and the event time is outside the tracking window, consider this as new login failure attempt then drop the host from the HashMap and perform step 3(a)
   Else
        Login attempt is successful. Check if the map contains the host entry (login failure being tracked).
        If the host is being already tracked, then create a 5 minute no-access window and log the record in the file.
        If the host is not being tracked, then do nothing.

### Additional Info

While reading the input file, each record will be validated for correctness (based on the format defined) and any invalid entries will be logged to error_records.txt

Input File: log.txt
Output File: error_records.txt


# Application Environment

Python based implementation tested on `Python 2.7.10`

# How to run

python ./src/log_analyzer.py ./log_input/log.txt ./log_output/