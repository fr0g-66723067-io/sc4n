class Inert:
    def __reduce__(self):
        return exec, ("print(1)",)


value = Inert()
