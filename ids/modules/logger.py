import datetime

class IDSLogger:
    def __init__(self, config, messageBus):
        self.config = config
        self.enabled = self.config.getboolean('Logger', 'enabled')
        self.log_to_console = self.config.getboolean('Logger', 'log_to_console')
        if self.enabled:
            # open log file in write mode
            logFilePath = self.config.get('Logger', 'log_file')
            self.logFile = open(logFilePath, "w")
            # subscribe logger to message bus
            self.messageBus = messageBus
            if self.config.getboolean('Logger', 'log_info'):
                self.messageBus.subscribe("Event.Log.Info", self, self.onInfo)
            if self.config.getboolean('Logger', 'log_notice'):
                self.messageBus.subscribe("Event.Log.Notice", self, self.onNotice)
            if self.config.getboolean('Logger', 'log_error'):
                self.messageBus.subscribe("Event.Log.Error", self, self.onError)

    def onInfo(self, message):
        noticeMessage = "Info: %s" % message
        self.log(noticeMessage)

    def onNotice(self, message):
        noticeMessage = "Notice: %s" % message
        self.log(noticeMessage)

    def onError(self, message):
        errorMessage = "Error: %s" % message
        self.log(errorMessage)

    def log(self, message):
        self.logFile.write(str(datetime.datetime.now()) + "\n")
        self.logFile.write(message + "\n\n")
        if self.log_to_console:
            print message + "\n"
