#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer

from scoring import get_score, get_interests

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


class CharField(object):
    def __init__(self, value=None, required: bool = True, nullable: bool = False):
        if required and value is None:
            raise ValueError("value is required")
        if not nullable and value is None:
            raise ValueError("value cannot be nullable")
        if value is None:
            self._value = value
            return
        assert isinstance(value, str), "value should be string"
        if self.__class__.__name__ != "CharField":
            return
        self._value = value

    @property
    def value(self):
        return self._value


class ArgumentsField(object):
    def __init__(self, value=None, required: bool = True, nullable: bool = False):
        assert isinstance(value, dict), "arguments should be mapping"
        if required and value is None:
            raise ValueError("arguments is required")
        if not nullable and value is None:
            raise ValueError("arguments cannot be empty")
        self._value = value

    @property
    def arguments(self):
        return self._value


class EmailField(CharField):
    def __init__(self, value="", required: bool = True, nullable: bool = False):
        try:
            super().__init__(value, required, nullable)
        except AssertionError:
            raise TypeError("email should be string")
        except ValueError as e:
            if str(e) == "value cannot be nullable":
                raise ValueError("email cannot be nullable")
            elif str(e) == "value is required":
                raise ValueError("email is required")
        if value is None:
            self._value = value
            return
        if "@" not in value:
            raise ValueError("email should contain @")
        self._value = value

    @property
    def email(self):
        return self._value


class PhoneField(object):
    def __init__(self, value=None, required: bool = True, nullable: bool = False):
        if required and value is None:
            raise ValueError("phone is required")
        if not nullable and value is None:
            raise ValueError("phone cannot be nullable")
        if value is None:
            self._value = value
            return
        assert isinstance(value, str) or isinstance(value, int)
        if isinstance(value, str) and not (value.startswith("7") or len(value) != 11):
            raise ValueError("Phone should starts with 7 and have length 11 symbols")
        if isinstance(value, int) and value // 10 ** 10 != 7:
            raise ValueError("Phone should starts with 7 and have length 11 symbols")
        self._value = value

    @property
    def phone(self):
        return self._value


class DateField(object):
    def __init__(self, value=None, required: bool = True, nullable: bool = False):
        if required and value is None:
            raise ValueError("value is required")
        if not nullable and value is None:
            raise ValueError("value cannot be nullable")
        if self.__class__.__name__ != "DateField":
            return
        if value is None:
            self._value = value
            return
        try:
            self._value = datetime.datetime.strptime(value, "%d.%m.%Y")
        except ValueError:
            raise ValueError("date must be in format DD.MM.YYYY")

    @property
    def date(self):
        return self._value


class BirthDayField(DateField):
    def __init__(self, value=None, required: bool = True, nullable: bool = False):
        try:
            super().__init__(value, required, nullable)
        except ValueError as e:
            if str(e) == "value cannot be nullable":
                raise ValueError("date cannot be nullable")
            elif str(e) == "value is required":
                raise ValueError("date is required")
            elif str(e) == "date must be in format DD.MM.YYYY":
                raise ValueError("birthday must be in format DD.MM.YYYY")
        if value is None:
            self._value = value
            return
        if value and (datetime.datetime.now() - datetime.datetime.strptime(value, "%d.%m.%Y")
                      > datetime.timedelta(days=365 * 70)):
            raise ValueError("age should be less then 70")
        self._value = value

    @property
    def birthday(self):
        return self._value


class GenderField(object):
    def __init__(self, value=None, required: bool = True, nullable: bool = False):
        if required and value is None:
            raise ValueError("gender is required")
        if not nullable and value is None:
            raise ValueError("gender cannot be nullable")
        if value is None:
            self._value = value
            return
        assert isinstance(value, int), "gender should be valid integer"
        if value not in (0, 1, 2):
            raise ValueError("gender should be 0 or 1 or 2")
        self._value = value

    @property
    def gender(self):
        return self._value


class ClientIDsField(object):
    def __init__(self, value=None, required: bool = True, nullable: bool = False):
        if required and value is None:
            raise ValueError("client_ids is required")
        if not nullable and value is None:
            raise ValueError("client_ids cannot be nullable")
        if value is None:
            self._value = value
            return
        assert isinstance(value, list), "client_ids should be list"
        if not len(value):
            raise ValueError("client_ids cannot be empty")
        for el in value:
            assert isinstance(el, int), "id should be valid integer"
        self._value = value

    @property
    def client_ids(self):
        return self._value


class ClientsInterestsRequest(object):
    def __init__(self, client_ids, date):
        self._client_ids = ClientIDsField(client_ids, required=True)
        self._date = DateField(date, required=False, nullable=True)

    @property
    def client_ids(self):
        return self._client_ids

    @property
    def date(self):
        return self._date


class OnlineScoreRequest(object):
    def __init__(self, first_name, last_name, email, phone, birthday, gender):
        try:
            self._first_name = CharField(first_name, required=False, nullable=True)
        except Exception:
            raise TypeError("first_name should be string")
        try:
            self._last_name = CharField(last_name, required=False, nullable=True)
        except Exception:
            raise TypeError("last_name should be string")
        try:
            self._email = EmailField(email, required=False, nullable=True)
        except Exception as e:
            raise TypeError(f"{e}")
        try:
            self._phone = PhoneField(phone, required=False, nullable=True)
        except Exception as e:
            raise TypeError(f"{e}")
        try:
            self._birthday = BirthDayField(birthday, required=False, nullable=True)
        except Exception as e:
            raise TypeError(f"{e}")
        try:
            self._gender = GenderField(gender, required=False, nullable=True)
        except Exception as e:
            raise TypeError(f"{e}")

    @property
    def first_name(self):
        return self._first_name

    @property
    def last_name(self):
        return self._last_name

    @property
    def email(self):
        return self._email

    @property
    def phone(self):
        return self._phone

    @property
    def birthday(self):
        return self._birthday

    @property
    def gender(self):
        return self._gender


class MethodRequest(object):
    def __init__(self, account, login, token, arguments, method):
        try:
            self._account = CharField(account, required=False, nullable=True)
        except AssertionError:
            raise TypeError("account should be string")
        try:
            self._login = CharField(login, required=True, nullable=True)
        except AssertionError:
            raise TypeError("login should be string")
        try:
            self._token = CharField(token, required=True, nullable=True)
        except AssertionError:
            raise TypeError("token should be string")
        try:
            self._arguments = ArgumentsField(arguments, required=True, nullable=True)
        except AssertionError as e:
            raise TypeError(f"{e}")
        except ValueError as e:
            raise ValueError(f"{e}")
        try:
            self._method = CharField(method, required=True, nullable=False)
        except AssertionError:
            raise TypeError("method should be string")

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    @property
    def account(self):
        return self._account.value

    @property
    def login(self):
        return self._login.value

    @property
    def token(self):
        return self._token.value

    @property
    def arguments(self):
        return self._arguments.arguments

    @property
    def method(self):
        return self._method.value


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account + request.login + SALT).encode('utf-8')).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    response, code = None, None
    data = request["body"]
    try:
        method_request = MethodRequest(
            data["account"],
            data["login"],
            data["token"],
            data["arguments"],
            data["method"],
        )
    except Exception as e:
        return str(e), INVALID_REQUEST
    if not check_auth(method_request):
        return "Forbidden", FORBIDDEN
    if method_request.method == "online_score":
        ctx["has"] = method_request.arguments.keys()
        args_ = method_request.arguments
        try:
            online_score = OnlineScoreRequest(
                first_name=args_.get("first_name"),
                last_name=args_.get("last_name"),
                email=args_.get("email"),
                phone=args_.get("phone"),
                birthday=args_.get("birthday"),
                gender=args_.get("gender")
            )
        except Exception as e:
            return str(e), INVALID_REQUEST
        response = {
            "score": get_score(
                store=store,
                phone=online_score.phone.phone,
                first_name=online_score.first_name.value,
                last_name=online_score.last_name.value,
                birthday=online_score.birthday.birthday,
                gender=online_score.gender.gender,
                email=online_score.email.email,
            )
        } if not method_request.is_admin else {"score": 42}
        code = OK
    elif method_request.method == "clients_interests":
        args_ = method_request.arguments
        if args_.get("client_ids"):
            ctx["nclients"] = len(args_["client_ids"])
        else:
            ctx["nclients"] = 0
        try:
            client_interests = ClientsInterestsRequest(
                client_ids=args_.get("client_ids", None),
                date=args_.get("date", None)
            )
        except Exception as e:
            return str(e), INVALID_REQUEST
        response = {
            client_id: get_interests(store, cid=client_interests.client_ids.client_ids)
            for client_id in client_interests.client_ids.client_ids
        }
        code = OK
    return response, code


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
                    response, code = self.router[path]({"body": request, "headers": self.headers},
                                                       context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
