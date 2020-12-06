import unittest
import os
import importlib
from log_analyzer import LineParser, RULES, log_format

LINE_OK = '1.169.137.128 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/group/1769230/banners HTTP/1.1" 200 1020 "-" "Configovod" "-" "1498697422-2118016444-4708-9752747" "712e90144abee9" 0.628'


class AnalyserTests(unittest.TestCase):
	
	def test_line_parser(self):
		line_parser = LineParser(RULES, log_format)
		line = line_parser.parse(LINE_OK)
		self.assertTrue(isinstance(line, dict))
	
	def test_templates_exists(self):
		self.assertTrue(os.path.exists('report.html'), 'missing template report.html')
	

if __name__ == '__main__':
	unittest.main()
