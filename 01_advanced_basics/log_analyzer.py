import re
from datetime import datetime
import gzip
import os
import statistics
from string import Template
import json
import argparse
import logging
from collections import namedtuple


def load_config(file):
	default = {
		"REPORT_SIZE": 1000,
		"REPORT_DIR": 'reports',
		"ERROR_THRESHOLD": 20,
		"LOG_DIR": 'log',
		"LOGGER_FILE": None
	}
	
	if not os.path.exists(file):
		raise FileNotFoundError(f"файл {file} не найден")
	
	with open(file) as f:
		data = json.load(f)
		
	default.update(data)
	
	return default


def load_args():
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument("--config", help="path to json config file", default='config.json')
	return arg_parser.parse_args()


def set_logger(file):
	filename = None
	if file is not None:
		filename = os.path.abspath(file)
		os.makedirs(os.path.split(filename)[0], exist_ok=True)
	
	logging.basicConfig(
		level=10,
		filename=filename,
		format='[%(asctime)s] %(levelname).1s %(message)s',
		datefmt='%Y.%m.%d %H:%M:%S'
	)


class LineParser:
	def __init__(self, rules, log_format):
		self.rules = rules
		self.log_format = log_format
		self.compilers = [(token_type, re.compile(params[0]), params[1]) for token_type, params in self.rules.items()]
	
	def gen_text(self, line):
		pos = 0
		while pos < len(line):
			match = None
			for token_type, pattern, resp in self.compilers:
				match = pattern.match(line, pos)
				if match is None:
					continue
				pos = match.end()
				text = resp(match)
				if text != '_IGNORE_':
					yield text
					break
			if match is None and pos != len(line):
				raise SyntaxError(f"no match for pos {pos}, sample: {line[pos:]}")
	
	def parse(self, line):
		text = (i for i in self.gen_text(line))
		return dict(zip(self.log_format, text))


class NginxReport:
	__slots__ = ('day', 'config', 'data', 'total', 'errors', 'error_threshold', 'html_template')
	
	def __init__(self, day, cls_config):
		self.day = day
		self.config = cls_config
		self.data = dict()
		self.total = {'count': 0, 'time': 0}
		self.errors = 0
		self.error_threshold = self.config['ERROR_THRESHOLD']
		
		with open('report.html', 'r') as f:
			self.html_template = Template(f.read())
	
	def error_report(self):
		current = self.errors / self.total['count'] * 100
		if current > self.error_threshold:
			logging.error(f"errors in log: {self.errors}, {current}%")
	
	def is_url_exist(self, url):
		if url not in self.data:
			self.data[url] = list()

	def data_table(self):
		table = list()
		for url, time_list in iter(self.data.items()):
			time_sum = round(sum(time_list), 3)
			if time_sum <= self.config['REPORT_SIZE']:
				continue
			count_perc = len(time_list)
			time_max = max(time_list)
			tr = {
				'url': url,
				'count': count_perc,
				'count_perc': round(count_perc / self.total['count'], 3),
				'time_sum': time_sum,
				'time_perc': round(time_sum / self.total['time'], 3),
				'time_avg': round(statistics.mean(time_list), 3),
				'time_max': time_max,
				'time_med': round(statistics.median(time_list), 3),
			}
			table.append(tr)
		return table
	
	def make_html(self, table):
		report_path = os.path.join(self.config['REPORT_DIR'], f"report-{self.day.strftime('%Y.%m.%d')}.html")
		
		with open(report_path, 'w', encoding='utf-8') as f:
			f.write(self.html_template.safe_substitute(table_json=json.dumps(table)))
		

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';


LOG_FORMAT = (
	'remote_addr', 'remote_user', 'http_x_real_ip', 'time_local', 'request',
	'status', 'body_bytes_sent', 'http_referer',
	'http_user_agent', 'http_x_forwarded_for', 'http_X_REQUEST_ID', 'http_X_RB_USER',
	'request_time'
)

RULES = {
	'SPACE': (r'\s+', lambda x: '_IGNORE_'),
	'NO_DATA': (r'-|"-"', lambda x: None),
	'QUOTED_STRING': (r'"([^"]+)"', lambda x: x.group(1)),
	'DATE': (r'\[([^\]]+)\]', lambda x: datetime.strptime(x.group(1), '%d/%b/%Y:%H:%M:%S %z')),
	'RAW': (r'([^\s]+)', lambda x: x.group(1)),
}


def file_data(name):
	if name.endswith(".gz"):
		return gzip.open(name)
	else:
		return open(name, 'rb')


LastLog = namedtuple('LastLog', ('file', 'dt'))


def last_log(path):
	pattern = r'nginx-access-ui.log-(\d{8})(\.gz|)\Z'
	last = None
	matcher = re.compile(pattern)
	for name in iter(os.listdir(path)):
		is_matched = matcher.match(name)
		if is_matched is not None:
			try:
				file_dt = datetime.strptime(is_matched.group(1), '%Y%m%d')
				if last is None or last.dt < file_dt:
					last = LastLog(os.path.join(path, name), file_dt)
			except ValueError:
				logging.exception(f"cant parse date {is_matched.group(1)}", exc_info=True)
	
	return last
	

def main(args):
	conf = load_config(args.config)
	set_logger(conf['LOGGER_FILE'])
	logging.info(f"nginx reporter config: {json.dumps(conf)}")
	
	if not os.path.exists(conf['LOG_DIR']):
		raise FileNotFoundError(f"папка {conf['LOG_DIR']} не существует")
	
	os.makedirs(conf['REPORT_DIR'], exist_ok=True)
	
	log = last_log(conf['LOG_DIR'])
	if log is None:
		logging.info(f"nginx log not found")
		return
		
	old_report_file = os.path.join(
		conf['REPORT_DIR'],
		f"report-{log.dt.strftime('%Y.%m.%d')}.html"
	)
	if os.path.exists(old_report_file):
		logging.info(f"found report for day {log.dt}, skipping")
		return
	
	line_parser = LineParser(RULES, LOG_FORMAT)
	report = NginxReport(log.dt, conf)
	
	for item in file_data(log.file):
		report.total['count'] += 1
		
		try:
			line = line_parser.parse(item.decode('utf-8', 'backslashreplace'))
		except Exception:
			logging.error('line not parsed', exc_info=True)
			report.errors += 1
			continue
			
		is_request = re.compile(r"\w+.*/")
		if is_request.match(line['request']) is not None:
			req_url = line['request'].split()[1]
			req_time = float(line['request_time'])
			
			report.total['time'] += req_time
			
			report.is_url_exist(req_url)
			report.data[req_url].append(req_time)
		else:
			logging.error(f"URL not specified, request: {line['request']}")
			report.errors += 1
			
	data_table = report.data_table()
	report.make_html(data_table)
	report.error_report()


if __name__ == "__main__":
	sys_args = load_args()
	try:
		main(sys_args)
	except:
		logging.exception('analyzer exited', exc_info=True)
