#translated from https://github.com/NETWAYS/go-check/blob/master/threshold.go GPL-2.0 license 

import re

class Threshold:
    Inside = False
    Lower = 0
    Upper = 0

    def __init__(self, spec):
        self.parseThreshold(spec)

    def __str__(self):
        """
        String returns the plain representation of the Threshold
        """
        s = self.boundaryToString(self.Upper)

        if s == "~":
            s = ""

        if self.Lower != 0:
            s = self.boundaryToString(self.Lower) + ":" + s

        if self.Inside:
            s = "@" + s

        return s

    def doesViolate(self, value):
        """
        Compares a value against the threshold, and returns true if the value violates the threshold.
        """
        if self.Inside:
            return value >= self.Lower and value <= self.Upper
        else:
            return value < self.Lower or value > self.Upper

    # @ at the beginning
    def parseThreshold(self, spec):
        """
        Parse a Threshold from a string.
        //
        See Threshold for details.
        """
        try:
            thresholdNumberRe = '(-?\d+(?:\.\d+)?|~)'
            thresholdRe = re.compile('^(@)?(?:{}:)?(?:{})?$'.format(thresholdNumberRe, thresholdNumberRe))
            PosInf = float('inf')
            NegInf = float('-inf')

            parts = thresholdRe.findall(spec)
            parts = parts[0]
            if spec == "" or len(parts) == 0:
                print("could not parse threshold: {}".format(spec))
                raise BaseException

            if parts[0] != "":
                self.Inside = True

            if parts[1] == "~":
                self.Lower = NegInf
            elif parts[1] != "":
                try:
                    v = float(parts[1])
                except:
                    print("can not parse lower bound '{}'", parts[1])
                    raise BaseException

                self.Lower = v

            # Upper bound
            if parts[2] == "~" or (parts[2] == "" and parts[1] != ""):
                self.Upper = PosInf
            elif parts[2] != "":
                try:
                    v = float(parts[2])
                except:
                    print("can not parse lower bound '{}'", parts[2])
                    raise BaseException
                self.Upper = v
        except:
            raise Exception("Invalid IcingaThreshold")

    # In the threshold context, the sign derives from lower and upper bound, we only need the ~ notation
    def boundaryToString(self, value):
        """
        BoundaryToString returns the string representation of a Threshold boundary.
        """
        s = self.formatFloat(value)

        if s == "inf" or s == "-inf":
            s = "~"

        return s

        # remove trailing 0

    def formatFloat(self, value):
        """
        FormatFloat returns a string representation of floats, avoiding scientific notation and removes trailing zeros.
        """
        s = "{:.3f}".format(value)
        s = s.rstrip("0")
        s = s.rstrip(".")

        return s
