import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
import scoring

import traceback
import sys

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
	BAD_REQUEST: "Bad Request",
	FORBIDDEN: "Forbidden",
	NOT_FOUND: "Not Found",
	INVALID_REQUEST: "Invalid Request",
	INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
	UNKNOWN: "unknown",
	MALE: "male",
	FEMALE: "female",
}


class CharField():
	""" Field descriptor base class, calls validate before value is set.
Write validation errors in parents validation attribute

	Args:
		required (bool): field required
		nullable (bool): field can me None
		default: default value when field is not set

	"""

	def __init__(self, required=False, nullable=False):
		self.required = required
		self.nullable = nullable
		self.name = None
		self.desc_name = None

	def __get__(self, instance, owner):
		return getattr(instance, self.name)

	def __set_name__(self, owner, name):
		self.desc_name = name
		self.name = f"_{name}"

	def validation(self, value):
		return

	def __set__(self, instance, value):
		if all((value is None, self.required and not self.nullable)):
			raise ValueError(f"required value {self.desc_name} is not set")
		pass_validation = not value and self.nullable
		if not pass_validation:
			self.validation(value)
		setattr(instance, self.name, value)


class ArgumentsField(CharField):
	def validation(self, value):
		if isinstance(value, str):
			try:
				json.loads(value)
			except json.decoder.JSONDecodeError as e:
				raise ValueError(f"cant convert {self.desc_name} to json: {e}")
		if not isinstance(value, dict):
			raise ValueError(f"wrong type of {self.desc_name}: {type(value)}")

	def __set__(self, instance, value):
		setattr(instance, self.name, value or dict())


class NameField(CharField):
	def validation(self, value):
		if not isinstance(value, str):
			raise ValueError(f"{self.desc_name} must be string")


class EmailField(CharField):
	def validation(self, value):
		if not isinstance(value, str):
			raise ValueError(f"{self.desc_name} must be string")
		if '@' not in value:
			raise ValueError(f"{self.desc_name} must contain @")


class PhoneField(CharField):
	def validation(self, value):
		if not isinstance(value, (str, int)):
			raise ValueError(f"wrong phone type: {type(value)}")
		if len(str(value)) != 11:
			raise ValueError(f"strange phone number")
		if str(value)[0] != '7':
			raise ValueError(f"wrong phone code")


class GenderField(CharField):
	def validation(self, value):
		if not isinstance(value, int):
			raise ValueError(f"{self.desc_name} must be int")
		if value not in (0, 1, 2):
			raise ValueError(f"wrong {self.desc_name} value")


class ClientIDsField(CharField):
	def validation(self, value):
		if not isinstance(value, list):
			raise ValueError(f"{self.desc_name} must be an array")
		else:
			if len(value) == 0:
				raise ValueError(f"{self.desc_name} cannot be empty")
			if not all((isinstance(xx, int) for xx in value)):
				raise ValueError(f"{self.desc_name} not all values are integers")


class DateField(CharField):
	def validation(self, value):
		try:
			datetime.datetime.strptime(value, '%d.%m.%Y')
		except ValueError as e:
			raise ValueError(f"cant parse date {value}, {e}")


class BirthDayField(DateField):
	def validation(self, value):
		super(BirthDayField, self).validation(value)
		_dt = datetime.datetime.strptime(value, '%d.%m.%Y')
		now = datetime.datetime.now()
		if _dt < datetime.datetime(now.year - 70, now.month, now.day):
			raise ValueError("well, you are too old for this")


class Request:
	fields = list()

	def __init__(self, **kwargs):
		for field in self.fields:
			setattr(self, field, kwargs.get(field, None))
		self.validate()

	def update_context(self, ctx):
		return

	def validate(self):
		return


class ClientsInterestsRequest(Request):
	fields = ['client_ids', 'date']
	client_ids = ClientIDsField(required=True)
	date = DateField(required=False, nullable=True)

	def update_context(self, ctx):
		ctx['nclients'] = len(self.client_ids)


def clients_interests_handler(request, store):
	resp, status = dict(), OK
	for cid in request.arguments.get('client_ids', []):
		resp[cid] = scoring.get_interests(store, cid)
	return resp, status


class OnlineScoreRequest(Request):
	fields = ['first_name', 'last_name', 'email', 'phone', 'birthday', 'gender']
	first_name = NameField(required=False, nullable=True)
	last_name = NameField(required=False, nullable=True)
	email = EmailField(required=False, nullable=True)
	phone = PhoneField(required=False, nullable=True)
	birthday = BirthDayField(required=False, nullable=True)
	gender = GenderField(required=False, nullable=True)

	def update_context(self, ctx):
		has = list()
		for field in self.fields:
			attr = getattr(self, field)
			if attr is not None:
				has.append(field)
		ctx['has'] = has

	def validate(self):
		super(OnlineScoreRequest, self).validate()
		check = (
			self.phone is not None and self.email is not None,
			self.first_name is not None and self.last_name is not None,
			self.gender is not None and self.birthday is not None
		)
		if not any(check):
			raise ValueError(f"required value pairs is not set")


def online_score_handler(request, store):
	resp, status = {'score': None}, OK
	if request.is_admin:
		resp['score'] = 42
	else:
		params = {
			'store': store,
			'phone': request.arguments.get('phone', ''),
			'email': request.arguments.get('email', ''),
			'birthday': request.arguments.get('birthday', ''),
			'gender': request.arguments.get('gender', ''),
			'first_name': request.arguments.get('first_name', ''),
			'last_name': request.arguments.get('last_name', '')
		}
		resp['score'] = scoring.get_score(**params)
	return resp, status


class MethodRequest(Request):
	fields = ['account', 'login', 'token', 'arguments', 'method']
	account = CharField(required=False, nullable=True)
	login = CharField(required=True, nullable=True)
	token = CharField(required=True, nullable=True)
	arguments = ArgumentsField(required=True, nullable=True)
	method = CharField(required=True, nullable=False)

	@property
	def is_admin(self):
		return self.login == ADMIN_LOGIN


def check_auth(request):
	if request.is_admin:
		data = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
	else:
		data = "{}{}{}".format(request.account or '', request.login or '', SALT)

	digest = hashlib.sha512(data.encode()).hexdigest()
	if digest == request.token:
		return True
	return False


def method_handler(request, ctx, store):
	try:
		base = MethodRequest(**request['body'])

		if not check_auth(base):
			logging.warning(f"forbidden request from {base.account}/{base.login}, token: {base.token}")
			return ERRORS[FORBIDDEN], FORBIDDEN

		methods = {
			'online_score': {'cls': OnlineScoreRequest, 'handler': online_score_handler, },
			'clients_interests': {'cls': ClientsInterestsRequest, 'handler': clients_interests_handler, }
		}

		if base.method in methods:
			method = methods[base.method]
			runner = method['cls'](**base.arguments)
			runner.update_context(ctx)

			return method['handler'](base, store)

		return ERRORS[NOT_FOUND], NOT_FOUND
	except ValueError as e:
		logging.error(f"INVALID_REQUEST: {json.dumps(request['body'])}")
		return str(e), INVALID_REQUEST
	except Exception as e:
		logging.exception("Unexpected error: %s" % e)
		return ERRORS[INTERNAL_ERROR], INTERNAL_ERROR


class MainHTTPHandler(BaseHTTPRequestHandler):
	router = {
		"method": method_handler
	}
	store = None

	def get_request_id(self, headers):
		return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

	def do_POST(self):
		response, code = {}, OK
		context = {"request_id": self.get_request_id(self.headers)}
		request = None
		try:
			data_string = self.rfile.read(int(self.headers['Content-Length']))
			request = json.loads(data_string)
		except:
			code = BAD_REQUEST

		if request:
			path = self.path.strip("/")
			logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
			if path in self.router:
				try:
					response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
				except Exception as e:
					logging.exception("Unexpected error: %s" % e)
					code = INTERNAL_ERROR
			else:
				code = NOT_FOUND

		logging.debug(f"response: {response}, code: {code}")

		self.send_response(code)
		self.send_header("Content-Type", "application/json")
		self.end_headers()
		if code not in ERRORS:
			r = {"response": response, "code": code}
		else:
			r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
		context.update(r)
		logging.info(context)
		self.wfile.write(json.dumps(r).encode())


if __name__ == "__main__":
	op = OptionParser()
	op.add_option("-p", "--port", action="store", type=int, default=8080)
	op.add_option("-l", "--log", action="store", default=None)
	(opts, args) = op.parse_args()
	logging.basicConfig(
		filename=opts.log,
		level=logging.INFO,
		format='[%(asctime)s] %(levelname).1s %(message)s',
		datefmt='%Y.%m.%d %H:%M:%S'
	)
	server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
	logging.info("Starting server at %s" % opts.port)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass
	server.server_close()
