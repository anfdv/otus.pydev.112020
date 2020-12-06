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


logger = logging.getLogger()

config = {
	"REPORT_SIZE": 1000,
	"REPORT_DIR": 'reports',
	"ERROR_THRESHOLD": 20,
	"LOG_DIR": 'log',
	"LOGGER_FILE": None
}


def load_config(file):
	assert os.path.exists(file), f"файл {file} не найден"
	with open(file) as f:
		data = f.read()
	assert data, 'пустой конфиг'
	return json.loads(data)


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
		self.load_html_template()
	
	def error_report(self):
		current = self.errors / self.total['count'] * 100
		if current > self.error_threshold:
			logger.error(f"errors in log: {self.errors}, {current}%")
	
	def is_url_exist(self, url):
		if url not in self.data:
			self.data[url] = list()
	
	def load_html_template(self):
		with open('report.html', 'r') as f:
			self.html_template = Template(f.read())
	
	def make_html(self):
		table_json = list()
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
			table_json.append(tr)
		report_day = self.day.strftime('%Y.%m.%d')
		report_path = os.path.join(self.config['REPORT_DIR'], f"report-{report_day}.html")
		
		with open(report_path, 'w', encoding='utf-8') as f:
			f.write(self.html_template.safe_substitute(table_json=json.dumps(table_json)))
		
		self.error_report()


LastLog = namedtuple('LastLog', ('file', 'dt'))




# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';


log_format = (
	'remote_addr', 'remote_user', 'http_x_real_ip', 'time_local', 'request',
	'status', 'body_bytes_sent', 'http_referer',
	'http_user_agent', 'http_x_forwarded_for', 'http_X_REQUEST_ID', 'http_X_RB_USER',
	'request_time'
)

RULES = {
	'SPACE': ('\s+', lambda x: '_IGNORE_'),
	'NO_DATA': ('-|"-"', lambda x: None),
	'QUOTED_STRING': ('"([^"]+)"', lambda x: x.group(1)),
	'DATE': ('\[([^\]]+)\]', lambda x: datetime.strptime(x.group(1), '%d/%b/%Y:%H:%M:%S %z')),
	'RAW': ('([^\s]+)', lambda x: x.group(1)),
}

line_parser = LineParser(RULES, log_format)


def file_data(name):
	if name.endswith(".gz"):
		return gzip.open(name)
	else:
		return open(name, 'rb')


def last_log():
	pattern = r'nginx-access-ui.log-\d{8}(\.gz|)\Z'
	
	last = None
	for name in iter(os.listdir(config['LOG_DIR'])):
		matched = re.compile(pattern).match(name)
		if matched is not None:
			file_dt = datetime.strptime(os.path.split(name)[1].split('.')[1].split('-')[1], '%Y%m%d')
			if last is None or last.dt < file_dt:
				last = LastLog(os.path.join(config['LOG_DIR'], name), file_dt)
	
	if last is not None:
		old_reports = list()
		for name in iter(os.listdir(config['REPORT_DIR'])):
			rep_dt = datetime.strptime(''.join(name.split('-')[1].split('.')[:-1]), '%Y%m%d')
			old_reports.append(rep_dt)
		
		if last.dt in old_reports:
			logger.info(f"found report for day {last.dt}, skipping")
		else:
			return last



def main(args):
	config.update(load_config(args.config))
	set_logger(config['LOGGER_FILE'])

	assert os.path.exists(config['LOG_DIR']), f"папка {config['LOG_DIR']} не существует"
	os.makedirs(config['REPORT_DIR'], exist_ok=True)
	
	logger.info(f"nginx reporter config: {json.dumps(config)}")
	
	log = last_log()
	
	if log is not None:
		report = NginxReport(log.dt, config)
		
		for item in file_data(log.file):
			report.total['count'] += 1
			try:
				line = line_parser.parse(item.decode('utf-8', 'backslashreplace'))
			except Exception:
				logger.error('line not parsed', exc_info=True)
				report.errors += 1
				continue
			is_request = re.compile("\w+.*/")
			if is_request.match(line['request']) is not None:
				req_url = line['request'].split()[1]
				req_time = float(line['request_time'])
				
				report.total['time'] += req_time
				
				report.is_url_exist(req_url)
				report.data[req_url].append(req_time)
			else:
				logger.error(f"URL not specified, request: {line['request']}")
				report.errors += 1
		
		report.make_html()


if __name__ == "__main__":
	args = load_args()
	try:
		main(args)
	except:
		logger.exception('analyzer exited', exc_info=True)
