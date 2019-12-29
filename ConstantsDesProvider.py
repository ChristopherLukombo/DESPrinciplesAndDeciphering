from Constantes import *
from FileProvider import *

#
# ConstantsProvider Implementation for managing ConstantsDes.
#


class ConstantsDesProvider:

    def __init__(self):
        self.file_provider = FileProvider()

    #
    # Get an associative array with the constants of DES encryption
    # Exemple :
    # PI =  58	50	42	34	26	18	10	2
    #       60	52	44	36	28	20	12	4
    #       62	54	46	38	30	22	14	6
    #       64	56	48	40	32	24	16	8
    #       57	49	41	33	25	17	9	1
    #       59	51	43	35	27	19	11	3
    #       61	53	45	37	29	21	13	5
    #       63	55	47	39	31	23	15	7
    #
    def build_constants_by_key(self):
        text = self.file_provider.read_file(Constantes.CONSTANTES_DES)
        constants_by_key = dict()

        i = 1
        while i < 29:
            if len(self.__find_line(text, i)) > 0 and len(text.split(" ")[i - 1]) <= 10:
                if text.split(" ")[i - 1].find("\n\n") >= 0:
                    key = text.split(" ")[i - 1].split("\n\n")[1]
                else:
                    key = text.split(" ")[i - 1]
                # if key not in constants_by_key:
                if key not in constants_by_key:
                    constants_by_key[key] = self.__find_line(text, i)
            i += 1

        return constants_by_key

    def __find_line(self, text, index):
        line = []
        column = text.split(" ")[index]
        column_split = column.split("\t")

        for i in range(len(column_split)):
            if column_split[i].find("\n"):
                if column_split[i].isdigit():
                    line.append(int(column_split[i]))
                else:
                    if column_split[i].split("\n")[0].isdigit():
                        line.append(int(column_split[i].split("\n")[0]))
                    if len(column_split[i].split("\n")) > 1 and column_split[i].split("\n")[1].isdigit():
                        line.append(int(column_split[i].split("\n")[1]))
        return line