#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsapicli.py
#
# Copyright 2021 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for awsapicli.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging
import logging.config

import click
import click_spinner
import coloredlogs

from awsapilib import ControlTower
from awsapilib.console import (PasswordManager,
                               UnableToRequestResetPassword,
                               UnableToResetPassword,
                               AccountManager,
                               InvalidAuthentication,
                               UnableToDisableVirtualMFA)
from awsapilib.controltower import InvalidParentHierarchy, NonExistentOU, ControlTowerBusy
from awsapilib.authentication import InvalidCredentials
from .options import (common_options,
                      common_account_manager_options,
                      account_name_option,
                      email_option,
                      device_name_option,
                      password_option,
                      region_option,
                      captcha_option)
from .validators import (validate_arn,
                         validate_email,
                         validate_reset_link)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''24-12-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


# This is the main prefix used for logging
LOGGER_BASENAME = '''awsapicli'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


def setup_logging(options):
    """
    Sets up the logging.

    Needs the args to get the log level supplied

    Args:
        options: The options provided through the cli.


    """
    config_file = options.pop('log_config')
    log_level = options.pop('log_level')
    # This will configure the logging, if the user has set a config file.
    # If there's no config file, logging will default to stdout.
    if config_file:
        # Get the config for the logger. Of course this needs exception
        # catching in case the file is not there and everything. Proper IO
        # handling is not shown here.
        try:
            with open(config_file) as conf_file:
                configuration = json.loads(conf_file.read())
                # Configure the logger
                logging.config.dictConfig(configuration)
        except ValueError:
            print(f'File "{config_file}" is not valid json, cannot continue.')
            raise SystemExit(1)
    else:
        coloredlogs.install(level=log_level.upper())


def filter_set_options(options):
    """Filters out options that are not set."""
    return {key: value for key, value in options.items() if value}


@click.group()
def account():
    """Main entry point of the CLI."""


@account.command()
@common_options
@email_option
@region_option
@account_name_option
@click.option('-a',
              '--arn',
              'arn',
              required=True,
              type=str,
              callback=validate_arn,
              help='The arn of the role that can access Control Tower.')
@click.option('-o',
              '--organizational-unit',
              'organizational_unit',
              required=True,
              default='Custom',
              type=str,
              help='The OU to create the account under. Defaults to "Custom".')
@click.option('-h',
              '--parent-hierarchy',
              'parent_hierarchy',
              required=False,
              multiple=True,
              type=str,
              help='The parent hierarchy of the OU if any, space delimited. If you want the OU to be created '
                   'under Root/GrandParentOU/ParentOU the arguments would be `-h Root -h GrandParentOU -h ParentOU`')
@click.option('-p',
              '--product-name',
              'product_name',
              required=False,
              type=str,
              help='The product name of the account. Defaults to the account name if not set.')
@click.option('-se',
              '--sso-email',
              'sso_user_email',
              required=False,
              type=str,
              callback=validate_email,
              help='The email for an SSO user. It defaults to the account email if not set.')
@click.option('-sf',
              '--sso-first-name',
              'sso_first_name',
              required=False,
              type=str,
              help='The first name for an SSO user. It defaults to "Control".')
@click.option('-sl',
              '--sso-last-name',
              'sso_last_name',
              required=False,
              type=str,
              help='The last name for an SSO user. It defaults to "Tower".')
@click.option('-f',
              '--force-ou-hierarchy-creation',
              'force_parent_hierarchy_creation',
              required=False,
              is_flag=True,
              help='If set and a parent hierarchy is provided then then the tool will try to create it even if it does '
                   'not exist.')
def create(**options):
    """Create a new account through Control Tower."""
    setup_logging(options)
    arn = options.pop('arn')
    region = options.pop('region')
    click.echo('Trying to authenticate to Control Tower.')
    try:
        with click_spinner.spinner():
            tower = ControlTower(arn, region)
    except InvalidCredentials:
        click.echo('Unable to authenticate to Control Tower, credentials were either not provided, '
                   'were wrong, or expired')
        raise SystemExit(1)
    click.echo('Trying to create requested account.')
    try:
        with click_spinner.spinner():
            result = tower.create_account(**filter_set_options(options))
    except ControlTowerBusy:
        click.echo('Control Tower is busy, please try again in a while')
        raise SystemExit(1)
    except (NonExistentOU, InvalidParentHierarchy) as msg:
        click.echo(f'Failed to create account with error: {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if result else 'Failed'
    click.echo(f'{report_message} to create account {options.get("account_name")}')
    raise SystemExit(int(not result))


@account.command()
@common_options
@common_account_manager_options
@account_name_option
def update_name(**options):
    """Update the name of an account."""
    setup_logging(options)
    account_email = options.get("account_email")
    args = {'email': account_email,
            'password': options.get('password'),
            'region': options.get('region'),
            'mfa_serial': options.get('mfa_serial')}
    solver = options.get('solver')
    if solver:
        args['solver'] = solver
    try:
        click.echo(f'Please wait updating the name of account {account_email}')
        with click_spinner.spinner():
            account_manager = AccountManager(**args)
            result = account_manager.update_account_name(options.get('account_name'))
    except InvalidAuthentication as msg:
        click.echo(f'Unable to rename account, failed with message {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if result else 'Failed'
    click.echo(f'{report_message} in renaming account {account_email}')
    raise SystemExit(int(not result))


@account.command()
@common_options
@common_account_manager_options
@click.option('-n',
              '--new-email',
              'new_account_email',
              required=True,
              type=str,
              callback=validate_email,
              help='The email to update to.')
def update_email(**options):
    """Update the email of an account."""
    setup_logging(options)
    account_email = options.get("account_email")
    args = {'email': account_email,
            'password': options.get('password'),
            'region': options.get('region'),
            'mfa_serial': options.get('mfa_serial')}
    solver = options.get('solver')
    if solver:
        args['solver'] = solver
    try:
        click.echo(f'Please wait updating the email of account {account_email}')
        with click_spinner.spinner():
            account_manager = AccountManager(**args)
            result = account_manager.update_account_email(options.get('new_account_email'))
    except InvalidAuthentication as msg:
        click.echo(f'Unable to update email of account, failed with message {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if result else 'Failed'
    click.echo(f'{report_message} in updating email of account {account_email}')
    raise SystemExit(int(not result))


@account.command()
@common_options
@common_account_manager_options
def terminate(**options):
    """Terminate (suspend for 90 days first) an account."""
    setup_logging(options)
    account_email = options.get("account_email")
    args = {'email': account_email,
            'password': options.get('password'),
            'region': options.get('region'),
            'mfa_serial': options.get('mfa_serial')}
    solver = options.get('solver')
    if solver:
        args['solver'] = solver
    try:
        click.echo(f'Please wait while terminating account {account_email}')
        with click_spinner.spinner():
            account_manager = AccountManager(**args)
            result = account_manager.terminate_account()
    except InvalidAuthentication as msg:
        click.echo(f'Unable to authenticate as root, failed with message {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if result else 'Failed'
    click.echo(f'{report_message} in terminating account {account_email}')
    raise SystemExit(int(not result))


@account.command()
@common_options
@email_option
@captcha_option
def password_request_reset(**options):
    """Request a password reset for an account."""
    setup_logging(options)
    account_email = options.get("account_email")
    args = {}
    solver = options.get('solver')
    if solver:
        args['solver'] = solver
    try:
        click.echo(f'Please wait while requesting password reset for account {account_email}')
        with click_spinner.spinner():
            password_manager = PasswordManager(**args)
            result = password_manager.request_password_reset(account_email)
    except UnableToRequestResetPassword as msg:
        click.echo(f'Unable to request password reset, failed with message {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if result else 'Failed'
    click.echo(f'{report_message} to request password reset for account {account_email}')
    raise SystemExit(int(not result))


@account.command()
@common_options
@click.option('-r', '--reset-url', 'reset_url', required=True, type=str, prompt=True, callback=validate_reset_link)
@password_option
def password_reset(**options):
    """Reset the password of an account."""
    setup_logging(options)
    args = {}
    solver = options.get('solver')
    if solver:
        args['solver'] = solver
    password_manager = PasswordManager(**args)
    try:
        result = password_manager.reset_password(options.get('reset_url'), options.get('password'))
    except UnableToResetPassword as msg:
        click.echo(f'Unable to reset password, failed with message {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if result else 'Failed'
    click.echo(f'{report_message} in resetting password.')
    raise SystemExit(int(not result))


@account.command()
@common_options
@common_account_manager_options
@device_name_option
def mfa_activate(**options):
    """Activate virtual MFA on an account."""
    setup_logging(options)
    # account_manager = AccountManager(email, password, region, mfa_serial, solver=solver)
    # account_manager.mfa.delete_virtual_mfa(device.serial_number)
    # import io
    # import qrcode
    # qr = qrcode.QRCode()
    # qr.add_data("Some text")
    # f = io.StringIO()
    # qr.print_ascii(out=f)
    # f.seek(0)
    # print(f.read())
    click.echo(options)


@account.command()
@common_options
@common_account_manager_options
@device_name_option
def mfa_deactivate(**options):
    """Deactivate virtual MFA on an account."""
    setup_logging(options)
    account_email = options.get("account_email")
    device_name = options.get('device_name')
    args = {'email': account_email,
            'password': options.get('password'),
            'region': options.get('region'),
            'mfa_serial': options.get('mfa_serial')}
    solver = options.get('solver')
    if solver:
        args['solver'] = solver
    try:
        click.echo(f'Please wait while deleting MFA device {device_name}')
        with click_spinner.spinner():
            account_manager = AccountManager(**args)
            result = account_manager.mfa.delete_virtual_device(device_name)
    except (InvalidAuthentication, UnableToDisableVirtualMFA) as msg:
        click.echo(f'Unable to delete MFA device {device_name}, failed with message {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if result else 'Failed'
    click.echo(f'{report_message} in deleting MFA device {device_name}')
    raise SystemExit(int(not result))


@account.command()
@common_options
@common_account_manager_options
def billing_iam_activate(**options):
    """Activate IAM access to billing console on an account."""
    setup_logging(options)
    account_email = options.get("account_email")
    args = {'email': account_email,
            'password': options.get('password'),
            'region': options.get('region'),
            'mfa_serial': options.get('mfa_serial')}
    solver = options.get('solver')
    if solver:
        args['solver'] = solver
    try:
        click.echo(f'Please wait while activating IAM access in account {account_email}')
        with click_spinner.spinner():
            account_manager = AccountManager(**args)
            account_manager.iam.billing_console_access = True
    except InvalidAuthentication as msg:
        click.echo(f'Unable activate IAM access, failed with message {msg}')
        raise SystemExit(1)
    report_message = 'Succeeded' if account_manager.iam.billing_console_access else 'Failed'
    exit_status = int(not account_manager.iam.billing_console_access)
    click.echo(f'{report_message} in activating IAM access in account {account_email}')
    raise SystemExit(exit_status)
