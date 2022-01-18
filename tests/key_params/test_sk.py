import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from openssh_key.key_params.ed25519 import Ed25519PublicKeyParams
from openssh_key.key_params.sk import (
    SecurityKeyFlag,
    SecurityKey_ECDSA_NISTP256_PrivateKeyParams,
    SecurityKey_ECDSA_NISTP256_PublicKeyParams,
    SecurityKey_Ed25519_PrivateKeyParams, SecurityKey_Ed25519_PublicKeyParams)
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction

nistp256_key = ec.generate_private_key(ec.SECP256R1())

test_cases_public_bytes = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)

PARAMS_TEST_CASES = [
    {
        'cls': SecurityKey_ECDSA_NISTP256_PublicKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'application': PascalStyleFormatInstruction.STRING,
        },
        'valid_values': [{
            'identifier': 'nistp256',
            'q': nistp256_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'application': 'ssh:',
        }],
        'invalid_values': [
            (
                {
                    'identifier': 'nistp256',
                    'q': b'\x00',
                    'application': 'ssh:',
                },
                'The point does not lie on the elliptic curve indicated by '
                'the identifier'
            ),
            (
                {
                    'identifier': 'nistp384',
                    'q': nistp256_key.public_key().public_bytes(
                        Encoding.X962, PublicFormat.UncompressedPoint
                    ),
                    'application': 'ssh:',
                },
                'The curve identifier encoded in the public key does not '
                'correspond to the key type'
            )
        ]
    },
    {
        'cls': SecurityKey_ECDSA_NISTP256_PrivateKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'application': PascalStyleFormatInstruction.STRING,
            'flags': '>B',
            'key_handle': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'identifier': 'nistp256',
            'q': nistp256_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'application': 'ssh:',
            'flags': 0,
            'key_handle': b'aaaa',
            'reserved': b'',
        }],
    },
    {
        'cls': SecurityKey_Ed25519_PublicKeyParams,
        'format_instructions_dict': {
            'public': PascalStyleFormatInstruction.BYTES,
            'application': PascalStyleFormatInstruction.STRING,
        },
        'valid_values': [{
            'public': test_cases_public_bytes,
            'application': 'ssh:',
        }],
        'invalid_values': [(
            {
                'public': secrets.token_bytes(
                    Ed25519PublicKeyParams.KEY_SIZE - 1
                ),
                'application': 'ssh:',
            },
            'Public key not of length ' + str(Ed25519PublicKeyParams.KEY_SIZE)
        )]
    },
    {
        'cls': SecurityKey_Ed25519_PrivateKeyParams,
        'format_instructions_dict': {
            'public': PascalStyleFormatInstruction.BYTES,
            'application': PascalStyleFormatInstruction.STRING,
            'flags': '>B',
            'key_handle': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'public': test_cases_public_bytes,
            'application': 'ssh:',
            'flags': 0,
            'key_handle': b'aaaa',
            'reserved': b'',
        }]
    }
]


def test_flag():
    sk_private_key = SecurityKey_Ed25519_PrivateKeyParams({
        'public': test_cases_public_bytes,
        'application': 'ssh:',
        'flags': 0,
        'key_handle': 'aaaa',
        'reserved': b'',
    })
    for flag_indices in range(2 ** len(SecurityKeyFlag)):
        flag_total_value = 0
        for index, flag in enumerate(SecurityKeyFlag):
            flag_new_value = flag_indices // (2 ** index) % 2 == 1
            sk_private_key.set_flag(flag, flag_new_value)
            if flag_new_value:
                flag_total_value += flag.value
            assert sk_private_key.get_flag(flag) == flag_new_value
        assert sk_private_key['flags'] == flag_total_value
