""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError

from .operations import operations, _check_health

logger = get_logger('fsr-change-management')


class ChnageManagement(Connector):
    def execute(self, config, operation, params, *args, **kwargs):
        logger.info('In execute() Operation: {}'.format(operation))
        try:
            operation = operations.get(operation)
            return operation(config, params, *args, **kwargs)
        except Exception as err:
            logger.exception('{}'.format(err))
            raise ConnectorError('{}'.format(err))

    def check_health(self, config, *args, **kwargs):
        try:
            return _check_health(config, *args, **kwargs)
        except Exception as e:
            logger.exception("An exception occurred {}".format(e))
            raise ConnectorError(e)
