import re
import sys
from collections import OrderedDict
from datetime import datetime
from datetime import timedelta
from dateutil.parser import parse

host_counter_dict = {}
resource_bandwidth_dict = {}
time_window_counter_dict = {}
login_error_attempts_dict = {}
failed_login_records = []

begin_event_time = None
begin_event_time_as_string = None
end_event_time = None
begin_login_failure_time = None
end_login_failure_time = None

input_file = None
output_directory = None
error_records = None

month_dict = {'Jan': '01', 'Feb': '02', 'Mar': '03',
              'Apr': '04', 'May': '05', 'Jun': '06',
              'Jul': '07', 'Aug': '08', 'Sep': '09',
              'Oct': '10', 'Nov':'11', 'Dec': '12'}


# write top most active hosts in desc order into hosts.txt
def output_report(data,filename,log_value):
    outfile = open(filename, "w")
    sorted_dict = OrderedDict(sorted(data.items(), key=lambda (k,v): (v,k), reverse=True))
    for k, v in sorted_dict.items()[:10]:
        if log_value == 1:
            outfile.write("%s,%s\n" % (k, v))
        else:
            outfile.write("%s\n" % k)
    outfile.close()

def log_failed_login_attempts(filename):
    outfile = open(filename, "w")
    for rec in failed_login_records:
        outfile.write("%s\n" % rec)
    outfile.close()

def parse_record(line):
    line = line.rstrip('\r\n ').lstrip(' ')
    record = {}

    if not line:
        return {}

    # get the host by splitting the record for space and get the first indexed item
    tokens = re.split(' ', line)
    record["host"] = tokens[0]

    # get the event time
    event_time = str(re.findall(r'\[(.+?)\]', line)).strip('\'\[').strip('\]\'')
    record["event_time"] = event_time

    # get the resource uri
    resource = None
    http_rec = re.findall(r'\"(.+?)\"', line)
    http_tokens = re.split(" ", http_rec[0])
    for token in http_tokens:
        if "/" not in token:
            continue
        if "HTTP/1.0" in token:
            break
        if "/" in token:
            resource = token
            break

    if resource:
        record["resource"] = resource
    else:
        # invalid record
        error_records.write("%s \n" % line)
        return {}

    # get the response code
    size = len(tokens)
    response_code = tokens[size-2]
    record["response_code"] = response_code

    # get response bytes length
    response_byte_length = tokens[size-1]
    if response_byte_length is "-":
        response_byte_length = 0
    else:
        try:
            int(response_byte_length)
        except ValueError:
            # invalid record
            error_records.write("%s \n" % line)
            return {}
    record["response_byte_length"] = response_byte_length

    record["original_data"] = line

    return record


# Feature 1 - Top most active hosts in desc order
def analyze_host(record):
    host = record["host"]
    if host_counter_dict.has_key(host):
        host_counter_dict[host] = host_counter_dict[host] + 1
    else:
        host_counter_dict[host] = 1

# Feature 2 - top 10 resources with most consumed bandwidth
def analyze_bandwidth_usage(record):
    bandwidth = record["response_byte_length"]
    resource = record["resource"]
    bandwidth = long(bandwidth)
    if resource_bandwidth_dict.has_key(resource):
        resource_bandwidth_dict[resource] = resource_bandwidth_dict[resource] + bandwidth
    else:
        resource_bandwidth_dict[resource] = bandwidth

# Feature 3 - 10 Busiest 60-minute period
def analyze_time_window(record):
    global begin_event_time
    global end_event_time
    global begin_event_time_as_string

    event_time_str = record["event_time"]

    parsed_time = get_time(event_time_str)

    if begin_event_time:
        if parsed_time > end_event_time:
            time_window_counter_dict[event_time_str] = 1
            begin_event_time_as_string = event_time_str
            begin_event_time = parsed_time
            end_event_time = parsed_time + timedelta(hours=0, minutes=60)
        else:
            time_window_counter_dict[begin_event_time_as_string] = time_window_counter_dict[begin_event_time_as_string] + 1
    else:
        begin_event_time = parsed_time
        end_event_time = parsed_time + timedelta(hours=0, minutes=60)
        begin_event_time_as_string = event_time_str
        time_window_counter_dict[event_time_str] = 1

# Feature 4 - Find login anomaly
def analyze_failed_login_attempts(record):
    host = record["host"]
    resource = record["resource"]
    response_code = int(record["response_code"])
    event_time = get_time(record["event_time"])

    if "/login" not in resource:
        return

    if response_code == 401:
        if login_error_attempts_dict.has_key(host):
            host_record = login_error_attempts_dict[host]
            failed_attempts = host_record["failed_attempts"]
            end_time = host_record["end_time"]
            if failed_attempts >= 3:
                if event_time > end_time:
                    # treat this as a new failure
                    del login_error_attempts_dict[host]
                    create_host_failure_record(host, event_time)
                else:
                    failed_login_records.append(record["original_data"])
            else:
                host_record["failed_attempts"] = host_record["failed_attempts"] + 1
                if host_record["failed_attempts"] == 3:
                   host_record["block_time"] = event_time + timedelta(hours=0, minutes=5)
        else:
            create_host_failure_record(host, event_time)
    else:
        if login_error_attempts_dict.has_key(host):
            host_record = login_error_attempts_dict[host]
            if host_record.has_key("block_time"):
               block_time = host_record["block_time"]
               if event_time > block_time:
                  del login_error_attempts_dict[host]
               else:
                  failed_login_records.append(record["original_data"])


def create_host_failure_record(host, event_time):
    host_record = {}
    host_record["begin_time"] = event_time
    host_record["end_time"] = event_time + timedelta(hours=0, minutes=0, seconds=20)
    host_record["failed_attempts"] = int(1)
    login_error_attempts_dict[host] = host_record

def get_time(event_time_str):
    
    date_str = re.split('/', event_time_str)
    time_str = re.split(':', date_str[2])
    tz_str = re.split(' ', time_str[3])

    date = date_str[0]
    month = month_dict.get(date_str[1])
    year = time_str[0]
    hour = time_str[1]
    min = time_str[2]
    sec = tz_str[0]
    timezone = tz_str[1]

    event_time = date + "/" + month + "/" + year + " " + hour + ":" + min + ":" + sec + " " + timezone

    parsed_time = parse(event_time)
    return parsed_time

def process_records():
    # iterate input file
    with open(input_file) as fileobject:
        for line in fileobject:
            record = parse_record(line)
            if record:
                analyze_host(record)
                analyze_bandwidth_usage(record)
                analyze_time_window(record)
                analyze_failed_login_attempts(record)

def start_processing():
    process_records()
    output_report(host_counter_dict, output_directory + "hosts.txt", 1)
    output_report(resource_bandwidth_dict, output_directory + "resources.txt", 0)
    output_report(time_window_counter_dict, output_directory + "hours.txt", 1)
    log_failed_login_attempts(output_directory + "blocked.txt")
    error_records.close()

def main():
    global input_file
    global output_directory
    global error_records

    if len(sys.argv) != 3:
        print 'Usage: log_analyzer.py <input_file> <output_directory>'
        sys.exit()

    input_file = sys.argv[1]
    output_directory = sys.argv[2]
    error_records = open(output_directory + "error_records.txt", "w")

    print "application started " + str(datetime.now())
    start_processing()
    print "application ended " + str(datetime.now())

if __name__ == "__main__":
    main()