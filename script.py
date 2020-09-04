import json
import asyncio
import argparse

from aiohttp import InvalidURL, ClientConnectorError
from colorama import Fore
from yarl import URL
from typing import Dict, List

import aiohttp

SUCCESS_RESPONSE_CODE = 200
JWT_SECRETS_FILE_NAME = 'jwt.secrets.list'
JWT_SECRETS_FILE_URL: str = 'https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list'


class LeakedCookie:
    def __init__(self):
        self._url: URL = URL()

        self._cookies: Dict[str, str] = {}
        self._jwt_secrets: List[str] = []
        self._result: List[Dict[str, str]] = []

        self.quiet: bool = False
        self.print_cookies_mod: bool = False
        self._result_file: str = 'result.json'
        self._print_default: bool = False

    @classmethod
    async def run(cls):
        """
        starts async jobs from the main script file
        :return: None
        """
        # creating class
        obj = cls()

        # preparation
        obj.argument_parser()

        # makes request and receiving cookies
        await obj.make_request_to_target()

        # print if needs found cookies from the target
        if obj.print_cookies_mod:
            obj.print_cookies()

        # parsing cookies
        await obj.parse_cookies()

        # if not quiet print result to stdout
        if not obj.quiet:
            obj.print_result()

        # saving results to a file
        obj.save_result_to_file()

    def argument_parser(self) -> None:
        """
        Parsing arguments
        :return: None
        """
        # Construct the argument parser
        ap = argparse.ArgumentParser(description='Finds jwt secrets in cookies')
        # Add the arguments to the parser
        ap.add_argument('-u', '--url', required=True, help='url', type=str)

        ap.add_argument(
            '-o', '--output', required=False, help='file to save result in json', default='result.json', type=str)

        ap.add_argument(
            '-q', '--quiet', required=False, help='quiet mod, only save to file', action='store_true', default=False)
        ap.add_argument('-p', '--print-cookies', required=False, action='store_true', default=False,
                        help='print to stdout found cookie list')
        ap.add_argument('-n', '--no-color', required=False, action='store_true', default=False,
                        help='print without colors to stdout')

        # parse arg
        args = ap.parse_args()

        self.url = args.url

        if args.quiet:
            self.quiet = True
        if args.print_cookies:
            self.print_cookies_mod = True
        if args.no_color:
            self.print_default = True

        if args.output:
            self.result_file = args.output

    @property
    def url(self) -> URL:
        """
        getter for a target url
        :return: URL url
        """
        return self._url

    @url.setter
    def url(self, url: URL) -> None:
        """
        setting a target url
        :param url: str
        :return: None
        """
        self._url = URL(url)

    async def make_request_to_target(self) -> None:
        """
        do request to a target
        :return: None
        """
        headers = {'User-agent': 'Googlebot-News', 'Cookie': 'security=low;'}
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as s:
            try:
                async with s.get(self.url, headers=headers):
                    self.cookies = s.cookie_jar.filter_cookies(self.url)
            except InvalidURL:
                self.print_in_color(f'Wrong url: {self.url}', True)
                exit()
            except ClientConnectorError:
                self.print_in_color(
                    f'Cannot connect to host {self.url}.[nodename nor servname provided, or not known]', True)
                exit()

    @property
    def cookies(self) -> Dict:
        """
        getter for target cookies
        :return: Dict cookies
        """
        return self._cookies

    @cookies.setter
    def cookies(self, cookies: Dict[str, str]) -> None:
        """
        set cookie from aiohttp session
        :param cookies: Dict[str, str]
        :return: None
        """
        self._cookies = cookies

    @property
    def result(self) -> List[Dict[str, str]]:
        """
        list of found unsecure cookies
        :return: List[Dict[str, str]]
        """
        return self._result

    @result.setter
    def result(self, result: Dict[str, str]) -> None:
        """
        setter for result
        :param result: Dict[str, str]
        :return: None
        """
        self._result.append(result)

    @property
    def result_file(self) -> str:
        """
        file name for saving result in json format
        :return: str default result.json
        """
        return self._result_file

    @result_file.setter
    def result_file(self, file_name: str) -> None:
        """
        setter for result file name
        :param file_name: str
        :return: None
        """
        self._result_file = file_name

    @property
    def jwt_secrets(self) -> List[str]:
        """
        List of public-available JWT secrets from google search and GitHub dorks
        :return:
        """
        return self._jwt_secrets

    @jwt_secrets.setter
    def jwt_secrets(self, jwt_secrets: List[str]) -> None:
        """
        setter for jwt secrets
        :param jwt_secrets: List[str]
        :return: None
        """
        self._jwt_secrets = jwt_secrets

    def print_cookies(self) -> None:
        """
        prints cookies to stdout
        :return: None
        """
        self.print_in_color(str(self.cookies.items()))

    def print_result(self) -> None:
        """
        prints result to stdout
        :return: None
        """
        if self.result:
            self.print_in_color(f'Cookies found:', True)
        else:
            self.print_in_color(f'Success, no jwt secrets found')
        for value in self.result:
            for key, cookie in value.items():
                self.print_in_color(f'{key}: {cookie}', True)

    async def download_jwt_secrets(self) -> None:
        """
        tries to download list of jwt secrets from GitHub repo
        `https://github.com/wallarm/jwt-secrets`
        :return: None
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(JWT_SECRETS_FILE_URL) as response:
                    if response.status == SUCCESS_RESPONSE_CODE:
                        content = await response.text()
                        self.jwt_secrets = content.splitlines()
                    else:
                        raise Exception
            except (ClientConnectorError, Exception):
                with open(JWT_SECRETS_FILE_NAME, 'r') as file:
                    self.jwt_secrets = file.readlines()

    async def parse_cookies(self) -> None:
        """
        downloads file with jwt secrets then
        loops thought it to find jwt secrets in cookies
        :return: None
        """
        await self.download_jwt_secrets()

        for key, cookie in self.cookies.items():
            if cookie in self.jwt_secrets:
                self.result = {'title': key, 'cookie': cookie}

    def save_result_to_file(self):
        with open(self.result_file, 'w') as file:
            file.write(str(json.dumps(self.result)))

    def print_in_color(self, text: str, danger: bool = False) -> None:
        """
        prints output in color or without
        depends on argument `--no-color`
        green for success results
        red if jwt secret found
        :param text: str text to print
        :param danger: bool print in green or red color
        :return: None
        """
        if self.print_default:
            print(text)
        else:
            if danger:
                print(f'{Fore.RED}{text}')
            else:
                print(f'{Fore.GREEN}{text}')

    @property
    def print_default(self) -> bool:
        """
        propriety to print in color or not
        :return: bool
        """
        return self._print_default

    @print_default.setter
    def print_default(self, default: bool) -> None:
        """
        setter for print in color ot not
        :param default: bool
        :return: None
        """
        self._print_default = default


async def main():
    await LeakedCookie.run()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
