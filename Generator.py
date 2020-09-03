# MIT License
#
# (c) 2020 pilao
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from datetime import date
from hashlib import sha1
from io import BytesIO
import base64
import lxml.etree
import random
import secrets


class Generator:
    def __init__(self, data: str):
        doc = lxml.etree.fromstring(base64.b64decode(data).decode('utf-8'))
        root = doc.xpath('/vmp-lm-product[1]')
        if not root:
            raise ValueError('not a product information string')
        product = root[0].xpath('@product[1]')
        if not product:
            raise ValueError('information about product is missed')
        self.__product_code = base64.b64decode(product[0])
        if len(self.__product_code) != 8:
            raise ValueError('product code has incorrect length')

        algorithm = root[0].xpath('@algorithm[1]')
        if not algorithm:
            raise ValueError('missed encryption algorithm')
        if algorithm[0] != 'RSA':
            raise ValueError('unsupported encryption algorithm')

        try:
            self.__bits = int(root[0].xpath('@bits[1]')[0])
            self.__exp = int.from_bytes(base64.b64decode(root[0].xpath('@exp[1]')[0]), 'big')
            self.__mod = int.from_bytes(base64.b64decode(root[0].xpath('@mod[1]')[0]), 'big')
        except NameError:
            raise ValueError('missed data for RSA algorithm')

    @staticmethod
    def __store_date(s: BytesIO, d: date):
        s.write(bytes([d.day]))
        s.write(bytes([d.month]))
        s.write(bytes([d.year % 256]))
        s.write(bytes([int(d.year / 256)]))

    def __build_serial_number(self,
                              username: str = None,
                              email: str = None,
                              hardware_id: str = None,
                              exp_date: date = None,
                              running_time_limit: int = None,
                              user_data: bytes = None,
                              max_build_date: date = None) -> bytes:
        with BytesIO() as s:
            # 1 byte of data - version
            s.write(b'\x01')
            s.write(b'\x01')

            if username is not None:
                # 1 + N bytes - length + N bytes of customer's name (without ending \0).
                s.write(b'\x02')
                buffer = username.encode('utf-8')
                count = len(buffer)
                if count > 255:
                    raise ValueError(f'username is too long: {count} bytes in UTF-8, maximum is 255')
                s.write(bytes([count]))
                s.write(buffer)

            if email is not None:
                # 1 + N bytes - length + N bytes of customer's name (without ending \0).
                s.write(b'\x03')
                buffer = email.encode('utf-8')
                count = len(buffer)
                if count > 255:
                    raise ValueError(f'email is too long: {count} bytes in UTF-8, maximum is 255')
                s.write(bytes([count]))
                s.write(buffer)

            if hardware_id is not None:
                # 1 + N bytes - length + N bytes of hardware id (N % 4 == 0)
                s.write(b'\x04')
                buffer = base64.b64decode(hardware_id)
                count = len(buffer)
                if count == 0:
                    raise ValueError('hardware_id has zero length, use "None" instead')
                if count > 255:
                    raise ValueError('hardware_id is too long')
                if count % 4 != 0:
                    raise ValueError('hardware_id has invalid length')
                s.write(bytes([count]))
                s.write(buffer)

            if exp_date is not None:
                # 4 bytes - (year << 16) + (month << 8) + (day)
                s.write(b'\x05')
                self.__store_date(s, exp_date)

            if running_time_limit is not None:
                # 1 byte - number of minutes
                s.write(b'\x06')
                s.write(bytes([running_time_limit]))

            # 8 bytes - used for decrypting some parts of exe-file
            s.write(b'\x07')
            s.write(self.__product_code)

            if user_data is not None:
                # 1 + N bytes - length + N bytes of user data
                s.write(b'\x08')
                count = len(user_data)
                if count > 255:
                    raise ValueError('user_data cannot exceed 255 bytes')
                if count == 0:
                    raise ValueError('user_data has zero length, use "None" instead')
                s.write(bytes([count]))
                s.write(user_data)

            if max_build_date is not None:
                # 4 bytes - (year << 16) + (month << 8) + (day)
                s.write(b'\x09')
                self.__store_date(s, max_build_date)

            checksum = bytearray(sha1(s.getbuffer()).digest()[:4])
            checksum.reverse()

            # 4 bytes - checksum: the first four bytes of sha-1 hash from the data before that chunk
            s.write(b'\xff')
            s.write(checksum)
            return s.getvalue()

    def __add_padding(self, bs: bytes) -> bytes:
        min_padding = 8 + 3
        max_padding = min_padding + 16
        max_bytes = int(self.__bits / 8)
        if len(bs) + min_padding > max_bytes:
            raise ValueError('Serial number is too long for this algorithm')

        max_padding_according_to_max_bytes = max_bytes - len(bs)
        if max_padding_according_to_max_bytes < max_padding:
            max_padding = max_padding_according_to_max_bytes

        padding_bytes = min_padding
        if max_padding > min_padding:
            padding_bytes += random.randint(0, max_padding - min_padding)

        with BytesIO() as s:
            s.write(b'\x00')
            s.write(b'\x02')
            s.write(secrets.token_bytes(padding_bytes))
            s.write(b'\x00')
            s.write(bs)

            rest = max_bytes - len(s.getbuffer())
            s.write(secrets.token_bytes(rest))
            return s.getvalue()

    def __encrypt(self, b: bytes) -> bytes:
        value = int.from_bytes(b, 'big')
        return pow(value, self.__exp, self.__mod).to_bytes(len(b), 'big')

    def generate(self,
                 username: str = None,
                 email: str = None,
                 hardware_id: str = None,
                 exp_date: date = None,
                 running_time_limit: int = None,
                 user_data: bytes = None,
                 max_build_date: date = None) -> str:
        return base64.encodebytes(
            self.__encrypt(
                self.__add_padding(
                    self.__build_serial_number(username,
                                               email,
                                               hardware_id,
                                               exp_date,
                                               running_time_limit,
                                               user_data,
                                               max_build_date)))).decode('utf-8')
