import json
import asyncio
import argparse
from typing import Dict, List, NamedTuple

from yarl import URL
from colorama import Fore
from attr import attrs, attrib, Factory

import aiohttp
from aiohttp import InvalidURL, ClientConnectorError

SUCCESS_RESPONSE_CODE = 200
JWT_SECRETS_FILE_NAME = 'jwt.secrets.list'
JWT_SECRETS_FILE_URL: str = 'https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list'


class RunConfig(NamedTuple):
    url: str
    output: str = 'result.json'
    quiet: bool = False
    print_cookies: bool = False
    no_color: bool = True


class PrettyPrint:

    def __init__(self, no_color: bool = False):
        self.no_color: bool = no_color

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
        if self.no_color:
            print(text)
        else:
            if danger:
                print(f'{Fore.RED}{text}')
            else:
                print(f'{Fore.GREEN}{text}')

    def print_result(self, result: List[Dict[str, str]]) -> None:
        """
        prints result to stdout
        :type result: List[Dict[str, str]]
        :return: None
        """
        if result:
            self.print_in_color(f'\n[!] Secrets in cookies found:', True)
            for value in result:
                for key, cookie in value.items():
                    self.print_in_color(f'{key}: {cookie}', True)
        else:
            self.print_in_color(f'\n[+] Success, no jwt secrets found')

    def print_cookies(self, cookies: Dict) -> None:
        """
        prints cookies to stdout
        :return: None
        """
        self.print_in_color(f'\nReceived cookies:')
        for key, value in cookies.items():
            self.print_in_color(f'{key}: {value}')


class Requests:

    @staticmethod
    async def make_request_to_target(url: URL, printer: PrettyPrint) -> Dict:
        """
        do request to a target
        :return: None
        """
        headers = {'User-agent': 'Googlebot-News', 'Cookie': 'security=low;'}
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as s:
            try:
                async with s.get(url, headers=headers):
                    return s.cookie_jar.filter_cookies(url)
            except InvalidURL:
                printer.print_in_color(f'Wrong url: {url}', True)
                exit()
            except ClientConnectorError:
                printer.print_in_color(
                    f'Cannot connect to host {url}.[nodename nor servname provided, or not known]', True)
                exit()

    @staticmethod
    async def download_jwt_secrets() -> List[str]:
        """
        tries to download list of jwt secrets from GitHub repo
        `https://github.com/wallarm/jwt-secrets`
        :return: List[str] list with jwt secrets line by line
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(JWT_SECRETS_FILE_URL) as response:
                    if response.status == SUCCESS_RESPONSE_CODE:
                        content = await response.text()
                        return content.splitlines()
                    else:
                        raise Exception
            except (ClientConnectorError, Exception):
                return ReadWriteDocuments.read_jwt_secrets_file()


class ReadWriteDocuments:

    def __init__(self, result_file: str):
        self.result_file: str = result_file

    def save_result_to_file(self, result: List[Dict[str, str]]) -> None:
        with open(self.result_file, 'w') as file:
            file.write(str(json.dumps(result)))

    @staticmethod
    def read_jwt_secrets_file() -> List[str]:
        with open(JWT_SECRETS_FILE_NAME, 'r') as file:
            return file.readlines()


class CookiesParser:

    def __init__(self, cookies: Dict[str, str]):
        self._cookies: Dict[str, str] = cookies
        self._jwt_secrets: List[str] = []

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

    async def parse_cookies(self) -> List[Dict[str, str]]:
        """
        downloads file with jwt secrets then
        loops thought it to find jwt secrets in cookies
        :return: List[Dict[str, str]]
        """
        result = []
        self._jwt_secrets = await Requests.download_jwt_secrets()

        for key, cookie in self.cookies.items():
            if cookie in self.jwt_secrets:
                result.append({'title': key, 'value': cookie})
        return result


@attrs
class LeakedCookie:
    config: RunConfig = attrib()
    _result: List[Dict[str, str]] = attrib(default=Factory(dict))

    @classmethod
    async def from_config(cls, config: RunConfig) -> 'LeakedCookie':
        return cls(config=config)

    async def run(self) -> None:
        """
        starts async jobs from the main script file
        :return: None
        """

        # create pretty printer
        printer = PrettyPrint(self.config.no_color)

        # makes request to receive cookies
        cookies = await Requests.make_request_to_target(URL(self.config.url), printer)

        # create cookie parser
        cookie_parser = CookiesParser(cookies)
        # print if needs found cookies from the target
        if self.config.print_cookies and cookies:
            printer.print_cookies(cookies)

        # parsing cookies
        self.result = await cookie_parser.parse_cookies()

        # if not quiet print result to stdout
        if not self.config.quiet:
            printer.print_result(self.result)

        # create write to file class
        file_handler = ReadWriteDocuments(self.config.output)
        # saving results to a file
        file_handler.save_result_to_file(self.result)

    @property
    def result(self) -> List[Dict[str, str]]:
        """
        list of found unsecure cookies
        :return: List[Dict[str, str]]
        """
        return self._result

    @result.setter
    def result(self, result: List[Dict[str, str]]) -> None:
        """
        setter for result
        :param result: Dict[str, str]
        :return: None
        """
        self._result = result


def define_config_from_cmd(parsed_args: 'argparse.Namespace') -> RunConfig:
    return RunConfig(
        url=parsed_args.url,
        output=parsed_args.output,
        quiet=parsed_args.quiet,
        print_cookies=parsed_args.print_cookies,
        no_color=parsed_args.no_color
    )


def cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Finds jwt secrets in cookies')
    # Add the arguments to the parser
    parser.add_argument('-u', '--url', required=True, help='url', type=str)

    parser.add_argument(
        '-o', '--output', required=False, help='file to save result in json', default='result.json', type=str)

    parser.add_argument(
        '-q', '--quiet', required=False, help='quiet mod, only save to file', action='store_true', default=False)
    parser.add_argument('-p', '--print-cookies', required=False, action='store_true', default=False,
                        help='print to stdout found cookie list')
    parser.add_argument('-n', '--no-color', required=False, action='store_true', default=False,
                        help='print without colors to stdout')

    return parser.parse_args()


async def main():
    parsed_args = cli()
    run_config = define_config_from_cmd(parsed_args=parsed_args)
    parser = await LeakedCookie.from_config(config=run_config)
    await parser.run()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
