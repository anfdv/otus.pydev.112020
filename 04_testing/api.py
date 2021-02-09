import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
import scoring


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


class CharField(abc.ABC):
	""" Field descriptor base class, calls validate before value is set.
Write validation errors in parents validation attribute

	Args:
		required (bool): field required
		nullable (bool): field can me None
		default: default value when field is not set

	"""

	def __init__(self, required=False, nullable=True, default=None):
		self.required = required
		self.nullable = nullable
		self.default = default
		self.name = None

	def __get__(self, instance, owner):
		return getattr(instance, self.name)

	def __set_name__(self, owner, name):
		self.name = f"_{name}"

	def validate(self, value):
		return list()

	def __set__(self, instance, value):
		validations = list()

		if value is None:
			if self.required or not self.nullable:
				validations.append(f"required value {self.name} is not set")
		else:
			validations += self.validate(value)

		setattr(instance, 'validation', validations)

		set_default = value is None and self.default is not None
		setattr(instance, self.name, self.default if set_default else value)


class FieldsValidation(abc.ABC):
	""" Validations descriptor, append incoming validation errors to existing list"""
	def __init__(self):
		self.name = None

	def __get__(self, instance, owner):
		if not hasattr(instance, self.name):
			return list()
		return getattr(instance, self.name)

	def __set_name__(self, owner, name):
		self.name = f"_{name}"

	def __set__(self, instance, value):
		if not hasattr(instance, self.name):
			val = list()
		else:
			val = getattr(instance, self.name)

		val += value
		setattr(instance, self.name, val)


class ArgumentsField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)
		if isinstance(value, str):
			try:
				json.loads(value)
			except json.decoder.JSONDecodeError as e:
				validation.append(f"cant convert {self.name} to json: {e}")

		if not isinstance(value, dict):
			validation.append(f"wrong type of {self.name}: {type(value)}")
		return validation


class NameField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)

		if not isinstance(value, str):
			validation.append(f"{self.name} must be string")

		return validation


class EmailField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)

		if not isinstance(value, str):
			validation.append(f"{self.name} must be string")
		if '@' not in value:
			validation.append(f"{self.name} must contain @")

		return validation


class PhoneField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)

		if not isinstance(value, (str, int)):
			validation.append(f"wrong phone type: {type(value)}")
		if len(str(value)) != 11:
			validation.append(f"strange phone number")
		if str(value)[0] != '7':
			validation.append(f"wrong phone code")

		return validation


class BirthDayField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)

		try:
			_dt = datetime.datetime.strptime(value, '%d.%m.%Y')
			now = datetime.datetime.now()
			if _dt < datetime.datetime(now.year - 70, now.month, now.day):
				validation.append("well, you are too old for this")
		except ValueError as e:
			validation.append(f"cant parse date {value}, {e}")

		return validation


class GenderField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)

		if not isinstance(value, int):
			validation.append(f"{self.name} must be int")

		if value not in (0, 1, 2):
			validation.append(f"wrong {self.name} value")

		return validation


class ClientIDsField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)

		if not isinstance(value, list):
			validation.append(f"{self.name} must be an array")
		else:

			if len(value) == 0:
				validation.append(f"{self.name} cannot be empty")

			if not all((isinstance(xx, int) for xx in value)):
				validation.append(f"{self.name} not all values are integers")

		return validation


class DateField(CharField):
	def validate(self, value):
		validation = super(self.__class__, self).validate(value)

		try:
			datetime.datetime.strptime(value, '%d.%m.%Y')
		except ValueError as e:
			validation.append(f"cant parse date {value}, {e}")

		return validation


class ClientsInterestsRequest(object):
	client_ids = ClientIDsField(required=True)
	date = DateField(required=False, nullable=True)
	validation = FieldsValidation()

	def __init__(self, client_ids=None, date=None):
		self.client_ids = client_ids
		self.date = date
		self.nclients = 0

	def post(self, method):
		resp = dict()
		for cid in self.client_ids:
			resp[cid] = scoring.get_interests(method.store, cid)
		return resp, OK

	def update_context(self):
		self.nclients = len(self.client_ids)

	def validate(self):
		if self.client_ids is not None:
			return True
		else:
			return False


class OnlineScoreRequest(object):
	first_name = NameField(required=False, nullable=True)
	last_name = NameField(required=False, nullable=True)
	email = EmailField(required=False, nullable=True)
	phone = PhoneField(required=False, nullable=True)
	birthday = BirthDayField(required=False, nullable=True)
	gender = GenderField(required=False, nullable=True)
	validation = FieldsValidation()

	def __init__(self, first_name=None, last_name=None, email=None, phone=None, birthday=None, gender=None):
		self.first_name = first_name
		self.last_name = last_name
		self.email = email
		self.phone = phone
		self.birthday = birthday
		self.gender = gender
		self.fields = ('first_name', 'last_name', 'email', 'phone', 'birthday', 'gender')
		self.has = list()

	def post(self, method):
		if method.is_admin:
			score = 42
		else:
			params = {
				'store': method.store,
				'phone': self.phone,
				'email': self.email,
				'birthday': self.birthday,
				'gender': self.gender,
				'first_name': self.first_name,
				'last_name': self.last_name
			}
			score = scoring.get_score(**params)
		return {'score': score}, OK

	def update_context(self):
		for field in self.fields:
			attr = getattr(self, field)
			if attr is not None:
				self.has.append(field)

	def validate(self):
		check = (
			self.phone is not None and self.email is not None,
			self.first_name is not None and self.last_name is not None,
			self.gender is not None and self.birthday is not None
		)
		return any(check)


class MethodRequest(object):
	account = CharField(required=False, nullable=True, default='')
	login = CharField(required=True, nullable=True, default='')
	token = CharField(required=True, nullable=True)
	arguments = ArgumentsField(required=True, nullable=True)
	method = CharField(required=True, nullable=False)
	validation = FieldsValidation()

	def __init__(self, account=None, login=None, token=None, arguments=None, method=None, ctx=None, store=None):
		self.account = account
		self.login = login
		self.token = token
		self.arguments = arguments
		self.method = method
		self.ctx = ctx
		self.store = store

	@property
	def is_admin(self):
		return self.login == ADMIN_LOGIN

	def handler(self, runner):
		if runner is not None:
			if not runner.validate():
				return ERRORS[INVALID_REQUEST], INVALID_REQUEST

			if runner.validation:
				logging.debug(f"invalid arguments: {runner.validation}")
				return '\n'.join(runner.validation), INVALID_REQUEST

			runner.update_context()
			if self.method == 'online_score':
				self.ctx['has'] = runner.has
			elif self.method == 'clients_interests':
				self.ctx['nclients'] = runner.nclients

			return runner.post(self)
		else:
			return ERRORS[INTERNAL_ERROR], INTERNAL_ERROR


def check_auth(request):
	if request.is_admin:
		data = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
	else:
		data = request.account + request.login + SALT

	digest = hashlib.sha512(data.encode()).hexdigest()
	if digest == request.token:
		return True
	return False


def method_handler(request, ctx, store):
	runner = None
	base = MethodRequest(ctx=ctx, store=store, **request['body'])

	if base.method == 'online_score':
		runner = OnlineScoreRequest(**base.arguments if base.arguments is not None else dict())
	elif base.method == 'clients_interests':
		runner = ClientsInterestsRequest(**base.arguments if base.arguments is not None else dict())

	if base.validation:
		logging.debug(f"invalid request parameters: {base.validation}")
		return '\n'.join(base.validation), INVALID_REQUEST

	if not check_auth(base):
		logging.warning(f"forbidden request from {base.account}/{base.login}, token: {base.token}")
		return ERRORS[FORBIDDEN], FORBIDDEN

	return base.handler(runner)


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
