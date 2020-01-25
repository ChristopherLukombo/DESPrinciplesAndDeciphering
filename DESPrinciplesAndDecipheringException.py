
#
# DESPrinciplesAndDecipheringException for managing Exception
#


class DESPrinciplesAndDecipheringException(Exception):

    def __init__(self, message, errors):
        super(DESPrinciplesAndDecipheringException, self).__init__(message)
        self.errors = errors
