#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: validation.py
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
validation package.

Import all parts from validation here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

import re

import click
from awsapilib import ControlTower
from awsapilib.captcha import Captcha2, InvalidOrNoBalanceApiToken

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''24-12-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


def validate_email(ctx, param, value):
    """Validates an email option."""
    if not value:
        return value
    try:
        if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", value):
            raise ValueError(value)
        return value
    except ValueError as msg:
        click.echo(f'Incorrect {param.name} given: {msg}')
        value = click.prompt(param.name)
        return validate_email(ctx, param, value)


def validate_region(ctx, param, value):
    """Validates a AWS region option."""
    try:
        if value not in ControlTower.get_available_regions():
            raise ValueError(value)
        return value
    except ValueError as msg:
        click.echo(f'Incorrect {param.name} given: {msg}')
        value = click.prompt(param.name)
        return validate_region(ctx, param, value)


def validate_arn(ctx, param, value):
    """Validates an AWS ARN option."""
    conditions = [value.startswith('arn:aws:iam::'),
                  value[13:25].isnumeric(),
                  value[25:31] == ':role/']
    try:
        if not all(conditions):
            raise ValueError(value)
        return value
    except ValueError as msg:
        click.echo(f'Incorrect {param.name} given: {msg}')
        value = click.prompt(param.name)
        return validate_arn(ctx, param, value)


def validate_token(ctx, param, value):  # pylint: disable=unused-argument
    """Validates a 2Captcha Token option and inserts an active 2Captcha instance in the options."""
    if not value:
        return None
    try:
        captcha = Captcha2(value)
        _ = captcha.solver.balance()
    except InvalidOrNoBalanceApiToken:
        raise click.BadParameter('The api token provided is not valid or no balance left of the account.')
    ctx.params['solver'] = captcha
    return value


def validate_reset_link(ctx, param, value):  # pylint: disable=unused-argument
    """Validates a reset link."""
    valid_prefix = 'https://signin.aws.amazon.com/resetpassword?type=RootUser&token='
    if not value.startswith(valid_prefix):
        raise click.BadParameter('The reset link provided is not valid.')
    return value
