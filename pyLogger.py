#!/usr/bin/python

import logging
import time
import inspect
import logging.handlers
import traceback
import threading
import sys

class Log(object):
    logLevel = 60
    logFile = 'LogFile.log'
    logStdOut = False
    handler = logging.handlers.RotatingFileHandler(filename=logFile, maxBytes=100000000, backupCount=2)
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter('%(threadName)s | %(levelname)s | %(message)s')
    errorFormat = logging.Formatter('%(name)s | %(processName)s | %(process)d | %(threadName)s | %(thread)d | %(asctime)s \n %(message)s')
    handler.setFormatter(formatter)
    startTime = time.time()

    @staticmethod
    def Fulltrace():
        """Returns the current line number in our program."""
        frame = inspect.currentframe()
        stack_trace = traceback.format_stack(frame)
        nstack = []
        for trace in stack_trace:
            temp = trace.replace(',', ' --')
            nstack.append(temp.replace('  ', ''))
        return nstack[:-2]

    @staticmethod
    def LastTrace():
        """Returns the current line number in our program."""
        frame = inspect.currentframe()
        stack_trace = traceback.format_stack(frame)
        nstack = []
        for trace in stack_trace:
            temp = trace.replace(',', ' --')
            nstack.append(temp.replace('  ', ''))
        return nstack[-3]

    @classmethod
    def setdataLogFile(cls, _name,_mode):
        class ThreadFilter(logging.Filter):
            def __init__(self, id):
                self.id = id
            def filter(self, record):
                return record.threadName == self.id
        _dataLogger = logging.getLogger(_name)
        if cls.logStdOut:
            _dataHandler = logging.StreamHandler(sys.stdout)
        else:
            _dataHandler = logging.FileHandler(_name, mode=_mode)
        _dataHandler.addFilter(ThreadFilter(threading.current_thread().name))
        _dataHandler.setFormatter(cls.formatter)
        _dataLogger.addHandler(_dataHandler)
        return _dataLogger, _dataHandler

    @classmethod
    def setLoglvl(cls, _lvl):
        cls.logLevel = _lvl
        cls.handler.setLevel(_lvl)
        cls.logger.addHandler(cls.handler)
        cls.logger.setLevel(_lvl)

    @classmethod
    def INFO(cls, msg1, msg2=''):
        if cls.logStdOut:
            cls.handler = logging.StreamHandler(sys.stdout)
        cls.handler.setFormatter(cls.formatter)
        cls.logger.addHandler(cls.handler)
        cls.logger.info('%s |           Time: %s\nInfoMsg: %s %s \n', cls.Fulltrace(), time.time()-cls.startTime, msg1, msg2)
        cls.logger.removeHandler(cls.handler)

    @classmethod
    def DEBUG(cls, msg1, msg2=''):
        if cls.logStdOut:
            cls.handler = logging.StreamHandler(sys.stdout)
        cls.handler.setFormatter(cls.formatter)
        cls.logger.addHandler(cls.handler)
        cls.logger.debug('%s |             Time: %s\nDbgMsg: %s %s \n', cls.Fulltrace(), time.time()-cls.startTime, msg1, msg2)
        cls.logger.removeHandler(cls.handler)

    @classmethod
    def ERROR(cls, msg1, msg2=''):
        if cls.logStdOut:
            cls.handler = logging.StreamHandler(sys.stdout)
        cls.handler.setFormatter(cls.errorFormat)
        cls.logger.addHandler(cls.handler)
        cls.logger.error('TRACE: %s | ErrorMsg: %s %s\n', cls.Fulltrace(), msg1, msg2)
        cls.logger.removeHandler(cls.handler)

    @classmethod
    def WARNING(cls, msg1, msg2=''):
        if cls.logStdOut:
            cls.handler = logging.StreamHandler(sys.stdout)
        cls.handler.setFormatter(cls.errorFormat)
        cls.logger.addHandler(cls.handler)
        cls.logger.warning('TRACE: %s | WarningMsg: %s %s\n', cls.LastTrace(), msg1, msg2)
        cls.logger.removeHandler(cls.handler)

    @classmethod
    def CRITICAL(cls, msg1, msg2=''):
        if cls.logStdOut:
            cls.handler = logging.StreamHandler(sys.stdout)
        cls.handler.setFormatter(cls.errorFormat)
        cls.logger.addHandler(cls.handler)
        cls.logger.critical('TRACE: %s | CRITICAL ERROR MESSAGE: %s %s\n', cls.Fulltrace(), msg1, msg2)
        cls.logger.removeHandler(cls.handler)

    @classmethod
    def DATA(cls, msg1, msg2='', _filename='data.log', mode='a'):
        def datalog(self, message, *args, **kws):
            DEBUG_LEVELV_NUM = 15
            logging.addLevelName(DEBUG_LEVELV_NUM, 'DATALOG')
            self.setLevel(cls.logLevel)
            if self.isEnabledFor(DEBUG_LEVELV_NUM):
                self._log(DEBUG_LEVELV_NUM, message, args, **kws)
        _dataLogger, _dataHandler = cls.setdataLogFile(_filename, mode)
        logging.Logger.datalog = datalog
        _dataLogger.datalog('Time: %s\n %s %s\n',  time.time()-cls.startTime, msg1, msg2)
        _dataLogger.removeHandler(_dataHandler)
