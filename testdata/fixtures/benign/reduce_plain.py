import pickle


class Plain:
    def __init__(self):
        self.x = 1

    def __reduce__(self):
        return (self.x, ())


pickle.dump(Plain(), open("plain.pkl", "wb"))
