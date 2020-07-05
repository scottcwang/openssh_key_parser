import enum
import io
import struct

OPENSSH_DEFAULT_STRING_LENGTH_SIZE = 4


class PascalStyleFormatInstruction(enum.Enum):
    # https://tools.ietf.org/html/rfc4251#section-5
    BYTES = enum.auto()
    STRING = enum.auto()
    MPINT = enum.auto()


class PascalStyleByteStream(io.BytesIO):
    def read_from_format_instruction(
        self,
        format_instruction,
        string_length_size=OPENSSH_DEFAULT_STRING_LENGTH_SIZE
    ):
        if isinstance(format_instruction, str):
            calcsize = struct.calcsize(format_instruction)
            read_bytes = self.read_fixed_bytes(calcsize)
            read_unpack = struct.unpack(format_instruction, read_bytes)
            if len(read_unpack) == 1:
                return read_unpack[0]
            return read_unpack
        elif isinstance(format_instruction, PascalStyleFormatInstruction):
            read_bytes = self.read_pascal_bytes(string_length_size)
            if format_instruction == PascalStyleFormatInstruction.BYTES:
                return read_bytes
            elif format_instruction == PascalStyleFormatInstruction.STRING:
                return read_bytes.decode()
            elif format_instruction == PascalStyleFormatInstruction.MPINT:
                return int.from_bytes(
                    read_bytes,
                    byteorder='big',
                    signed=True
                )
        raise NotImplementedError()

    def read_from_format_instructions_dict(self, format_instructions_dict):
        return {
            k: self.read_from_format_instruction(
                **(
                    format_instruction
                    if isinstance(format_instruction, dict)
                    else {'format_instruction': format_instruction}
                )
            )
            for k, format_instruction in format_instructions_dict.items()
        }

    def read_fixed_bytes(self, num_bytes):
        read_bytes = self.read(num_bytes)
        if len(read_bytes) < num_bytes:
            raise EOFError()
        return read_bytes

    def read_pascal_bytes(self, string_length_size):
        if string_length_size <= 0:
            raise ValueError('string_length_size must be positive')
        length = int.from_bytes(
            self.read_fixed_bytes(string_length_size),
            byteorder='big'
        )
        return self.read_fixed_bytes(length)

    def write_from_format_instruction(
        self,
        format_instruction,
        value,
        string_length_size=OPENSSH_DEFAULT_STRING_LENGTH_SIZE
    ):
        write_bytes = None
        if isinstance(format_instruction, str):
            write_bytes = struct.pack(format_instruction, value)
        elif isinstance(format_instruction, PascalStyleFormatInstruction):
            if format_instruction == PascalStyleFormatInstruction.BYTES:
                assert isinstance(value, bytes)
                write_bytes = value
            elif format_instruction == PascalStyleFormatInstruction.STRING:
                assert isinstance(value, str)
                write_bytes = value.encode()
            elif format_instruction == PascalStyleFormatInstruction.MPINT:
                assert isinstance(value, int)
                write_bytes = value.to_bytes(
                    length=(value.bit_length() + (8 if value > 0 else 7)) // 8,
                    byteorder='big',
                    signed=True
                )
            else:
                raise NotImplementedError()
            write_bytes_len_bytes = len(write_bytes).to_bytes(
                length=OPENSSH_DEFAULT_STRING_LENGTH_SIZE,
                byteorder='big',
                signed=False
            )
            write_bytes = write_bytes_len_bytes + write_bytes
        else:
            raise NotImplementedError()
        self.write(write_bytes)
        return

    def write_from_format_instructions_dict(
        self,
        format_instructions_dict,
        values_dict
    ):
        for k, v in format_instructions_dict.items():
            self.write_from_format_instruction(
                v,
                values_dict[k]
            )
