"""Error types for the ELF audit engine."""


class StructuralError(Exception):
    """The first structural violation found while parsing an object.

    Attributes:
        field:   ELF structure field or table the violation belongs to
                 (e.g. ``e_phoff``, ``PT_LOAD``, ``DT_SYMTAB``).
        message: Human readable description of the violation.
        offset:  File offset most relevant to the violation, or ``None``.
    """

    def __init__(self, field, message, offset=None):
        super().__init__(message)
        self.field = field
        self.message = message
        self.offset = offset

    def as_dict(self):
        return {"field": self.field, "message": self.message, "offset": self.offset}
