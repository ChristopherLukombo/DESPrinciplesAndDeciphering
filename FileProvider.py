

#
# FileProvider Implementation for managing files.
#


class FileProvider:

    def read_file(self, path):
        text = ""
        try:
            file = open(path)
            text = file.read()
            file.close()
        except OSError as e:
            print("Error, could not read file : {0}".format(e))
        return text