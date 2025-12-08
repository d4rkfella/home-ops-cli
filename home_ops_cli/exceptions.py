class RetryLimitExceeded(Exception):
    def __init__(self, last_exception: Exception, retries: int):
        self.last_exception = last_exception
        self.retries = retries
        super().__init__(f"Function failed after {retries} retries: {last_exception!r}")


class RetryableDownloadError(Exception):
    pass


class VMExportAlreadyExistsError(Exception):
    pass
